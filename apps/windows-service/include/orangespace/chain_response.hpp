#pragma once
#include <functional>
#include <string>
#include <utility>
namespace orangespace::service::chain {
// Internal transport ownership, never supplied by the wire caller. Unwinding,
// failed writes, timeout, malformed ACK and disconnect all have one rollback.
class Response {
  std::function<void(bool)> completion_;
public:
  std::string body;
  Response(std::string text={},std::function<void(bool)> completion={})
    :completion_(std::move(completion)),body(std::move(text)){}
  Response(const Response&)=delete;
  Response& operator=(const Response&)=delete;
  Response(Response&& other) noexcept
    :completion_(std::exchange(other.completion_,{})),body(std::move(other.body)){}
  Response& operator=(Response&& other) noexcept {
    if(this!=&other){finish(false);completion_=std::exchange(other.completion_,{});body=std::move(other.body);}return *this;
  }
  ~Response(){finish(false);}
  template<class Write,class ReadAck>
  bool deliver(Write&& write,ReadAck&& read_ack) {
    const bool accepted=write(body) && read_ack();
    finish(accepted); return accepted;
  }
  void finish(bool acknowledged) noexcept {
    auto completion=std::exchange(completion_,{});
    if(completion)try{completion(acknowledged);}catch(...){}
  }
};
}
