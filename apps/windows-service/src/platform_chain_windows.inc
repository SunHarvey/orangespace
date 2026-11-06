// Included inside chain_windows.cpp's protected Windows implementation namespace.
inline void mark_platform_authorization(const wchar_t** phase,const wchar_t* label) noexcept {
  if(phase)*phase=label;
}
// Bounded, exact exchange cleanup ownership. Failed cleanup is retained, never
// reported as success; retried on the next platform authorization (64 slots).
struct PlatformReceipt {
  std::mutex mutex;
  std::shared_ptr<node_session::TrustedCatalog> catalog;
  std::string node;
  std::optional<platform_session::ExchangeTicket> ticket;
  bool submitted{}, pending{}, complete{};
  void cleanup() {
    std::lock_guard lock(mutex);
    if(complete)return;
    if(!submitted){complete=true;return;}
    detail::require(ticket.has_value());
    Text body;
    body.value="{\"schema\":1,\"exchange_id\":"+quote(ticket->exchange_id)+",\"exchange_token\":"+quote(ticket->exchange_token.view())+"}";
    try {
      catalog->federation_exchange(node,body.value,true,[](std::string_view bytes){
        detail::exact_wire_integers(bytes);detail::JsonGuard doc(bytes);detail::object(doc.value,2);
        detail::require(detail::integer(detail::field(doc.value,"schema"))==1&&detail::text(detail::field(doc.value,"local_session_state"))=="revoked");
      });
    } catch(const node_session::ExchangeCleanupAbsent&) {
      // Only a validated response to the actual cleanup POST proves absence.
      // Preflight/status/trust/network failures retain this exact receipt.
    }
    complete=true;ticket.reset();
  }
  void abandon() noexcept {
    {std::lock_guard lock(mutex);pending=true;}
    try{cleanup();}catch(...){} // retained by the pool for explicit retry
  }
};
class PlatformReceipts {
  std::mutex mutex_;
  std::array<std::shared_ptr<PlatformReceipt>,64> slots_{};
public:
  std::shared_ptr<PlatformReceipt> reserve(std::shared_ptr<node_session::TrustedCatalog> catalog,std::string_view node) {
    std::lock_guard lock(mutex_);
    for(auto& s:slots_) if(s) {
      bool pending,complete;
      {std::lock_guard l(s->mutex);pending=s->pending;complete=s->complete;}
      if(pending&&!complete)try{s->cleanup();}catch(...){}
      {std::lock_guard l(s->mutex);complete=s->complete;}
      if(complete)s.reset();
    }
    for(auto& s:slots_)if(!s){auto r=std::make_shared<PlatformReceipt>();r->catalog=std::move(catalog);r->node=node;s=r;return r;}
    throw std::runtime_error("platform cleanup capacity exhausted");
  }
};
class PlatformNode final : public Session {
  mutable std::mutex mutex_;
  std::shared_ptr<node_session::TrustedCatalog> catalog_;
  std::shared_ptr<PlatformReceipt> receipt_;
  platform_session::Session central_;
  platform_session::NodeRef selected_;
  std::unique_ptr<node_session::NodeSession> node_;
  std::string local_alias_;
  void central_check() {
    auto all=central_.nodes();
    auto found=std::find_if(all.begin(),all.end(),[&](const auto& n){return n.node_id==selected_.node_id;});
    detail::require(found!=all.end());platform::same_node(selected_,*found);
    platform::match_catalog(*found,catalog_->federation_node(found->node_id));
  }
public:
  PlatformNode(std::shared_ptr<node_session::TrustedCatalog> catalog,std::shared_ptr<PlatformReceipt> receipt,
      platform_session::Session central,platform_session::NodeRef selected)
      :catalog_(std::move(catalog)),receipt_(std::move(receipt)),central_(std::move(central)),selected_(std::move(selected)) {
    local_alias_=catalog_->federation_node(selected_.node_id).name;
  }
  ~PlatformNode() override {receipt_->abandon();}
  void initialize(const wchar_t** phase=nullptr) {
    mark_platform_authorization(phase,L"platform-auth-center-node-check");
    central_check();
    mark_platform_authorization(phase,L"platform-auth-center-exchange-issue");
    receipt_->ticket.emplace(central_.issue(selected_.node_id));
    Text body;
    body.value="{\"schema\":1,\"exchange_id\":"+quote(receipt_->ticket->exchange_id)+",\"exchange_token\":"+quote(receipt_->ticket->exchange_token.view())+"}";
    receipt_->submitted=true; // before possibly submitting; unknown result retains cleanup
    mark_platform_authorization(phase,L"platform-auth-node-exchange");
    catalog_->federation_exchange(selected_.node_id,body.value,false,[&](std::string_view bytes){
      mark_platform_authorization(phase,L"platform-auth-node-exchange-response");
      detail::exact_wire_integers(bytes);detail::JsonGuard doc(bytes);
      const auto expiry=platform::validate_exchange(doc.value,central_.identity(),selected_,chain_now());
      const auto& credential=detail::field(doc.value,"node_credential");
      // Never rewrite an issued envelope to manufacture a catalog match. Origin
      // was checked exactly against Centre and equivalently against static pins.
      mark_platform_authorization(phase,L"platform-auth-node-identity");
      node_.reset(new node_session::NodeSession(node_session::NodeSession::restore(*catalog_,local_alias_,detail::text(detail::field(credential,"access_token")))));
      detail::require(node_->identity().user_id==selected_.remote_legacy_user_id&&node_->identity().node_id==selected_.node_id&&node_->expires_at()==expiry);
    });
    mark_platform_authorization(phase,L"platform-auth-center-node-recheck");
    central_check();
  }
  Identity identity() const override {
    std::lock_guard lock(mutex_);
    detail::require(node_!=nullptr);
    return {node_->identity().user_id,node_->identity().node_id,std::min(node_->expires_at(),central_.identity().expires_at),central_.identity().central_user_id};
  }
  void refresh() override {
    std::lock_guard lock(mutex_);detail::require(node_!=nullptr);central_check();
    Text saved(node_->credential_envelope());
    auto fresh=std::unique_ptr<node_session::NodeSession>(new node_session::NodeSession(node_session::NodeSession::restore_envelope(*catalog_,local_alias_,saved.value)));
    detail::require(fresh->identity().user_id==selected_.remote_legacy_user_id&&fresh->expires_at()==node_->expires_at());node_=std::move(fresh);
  }
  LeaseResult create(const Binding& b) override {std::lock_guard lock(mutex_);detail::require(node_!=nullptr);return node_->create_tunnel("{\"sandbox_id\":"+quote(b.sandbox)+",\"generation\":"+std::to_string(b.generation)+",\"tunnel_id\":"+quote(b.tunnel)+"}");}
  RenewResult renew(const Binding& b) override {std::lock_guard lock(mutex_);detail::require(node_!=nullptr);return node_->renew_tunnel(b.tunnel);}
  void revoke(const Binding& b) override {std::lock_guard lock(mutex_);detail::require(node_!=nullptr);node_->revoke_tunnel(b.tunnel);}
  void logout() override {
    std::lock_guard lock(mutex_);
    // Revoke this private Node credential only. Never central_.logout().
    receipt_->cleanup();node_.reset();
  }
};
