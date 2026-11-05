#pragma once
#include "orangespace/model.hpp"
namespace orangespace::ui_v2 {
// Broker create returns singular `sandbox`, unlike list. Validate its ownership.
inline Sandbox created_sandbox(std::string_view wire,const std::string& user) {
  const auto response=parse_response(wire,user);
  const auto doc=json::parse(wire);const auto* row=doc.find("sandbox");
  if(!response.ok || !row)throw std::runtime_error("missing created sandbox");
  Sandbox result{field(*row,"id"),field(*row,"user_id"),field(*row,"name"),field(*row,"node_id"),field(*row,"state"),field(*row,"profile_path")};
  if(!valid_uuid(result.id) || !valid_uuid(result.user_id) || canonical_uuid(result.user_id)!=canonical_uuid(user) ||
     (!result.node_id.empty() && !valid_uuid(result.node_id)))throw std::runtime_error("created sandbox identity rejected");
  return result;
}
// Stable local identity, never a label; closed rows remain eligible for restore.
inline std::optional<Sandbox> default_sandbox(const std::vector<Sandbox>& rows,
    const std::string& user, const std::string& node,const std::string& preferred={}) {
  for(const auto& row:rows)if(row.id==preferred && row.user_id==user && row.node_id==node && row.state!="deleting")return row;
  for(const auto& row:rows)if(valid_uuid(row.id) && valid_uuid(row.user_id) && valid_uuid(user) && valid_uuid(preferred) &&
      canonical_uuid(row.id)==canonical_uuid(preferred) && canonical_uuid(row.user_id)==canonical_uuid(user) &&
      (row.node_id.empty() || row.node_id==node) && row.state!="deleting")return row;
  const Sandbox* chosen=nullptr;
  for(const auto& row:rows)
    if(row.user_id==user && row.node_id==node && row.state!="deleting" &&
       (!chosen || row.id<chosen->id))chosen=&row;
  return chosen ? std::optional<Sandbox>(*chosen) : std::nullopt;
}
}
