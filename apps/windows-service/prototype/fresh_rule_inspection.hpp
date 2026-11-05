#pragma once
#include <array>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace orangespace::prototype {
// Shares only a fresh complete rule inspection, never admission/peer authority.
// Each request needs a capture STARTED after its registration. A request made
// during a capture cannot consume that capture, even if it has not completed.
class FreshRuleInspection {
public:
 using Digest=std::array<unsigned char,32>;
 explicit FreshRuleInspection(std::function<Digest()> capture)
  :capture_(std::move(capture)),worker_([this]{run();}){}
 FreshRuleInspection(const FreshRuleInspection&)=delete;
 FreshRuleInspection& operator=(const FreshRuleInspection&)=delete;
 ~FreshRuleInspection(){stop();if(worker_.joinable())worker_.join();}
 Digest snapshot(){std::unique_lock lock(mutex_);auto seq=issue_locked();cv_.notify_all();return wait_locked(lock,seq);}
 // Cancellation is irreversible; an in-flight callback is joined by destructor.
 void stop(){std::lock_guard lock(mutex_);stopped_=true;cv_.notify_all();}
private:
 friend struct FreshRuleInspectionTestAccess;
 std::function<Digest()> capture_;
 std::mutex mutex_;std::condition_variable cv_;
 std::uint64_t requested_=0,completed_=0;
 Digest latest_{};bool stopped_=false;std::exception_ptr failure_;
 std::thread worker_; // last: every captured member is initialized first
 void check_locked(){if(failure_)std::rethrow_exception(failure_);if(stopped_)throw std::runtime_error("rule inspection stopped");}
 std::uint64_t issue_locked(){
  check_locked();
  if(requested_==std::numeric_limits<std::uint64_t>::max()){
   stopped_=true;cv_.notify_all();throw std::runtime_error("rule inspection sequence exhausted");
  }
  return ++requested_;
 }
 Digest wait_locked(std::unique_lock<std::mutex>&lock,std::uint64_t seq){
  cv_.wait(lock,[&]{return stopped_||failure_||completed_>=seq;});
  check_locked();return latest_;
 }
 void run()noexcept{
  std::unique_lock lock(mutex_);
  for(;;){
   cv_.wait(lock,[&]{return stopped_||requested_>completed_;});if(stopped_)return;
   const auto claimed=requested_; // capture boundary under registration lock
   lock.unlock();Digest result{};
   try{result=capture_();}catch(...){lock.lock();failure_=std::current_exception();stopped_=true;cv_.notify_all();return;}
   lock.lock();if(stopped_){cv_.notify_all();return;}
   latest_=result;completed_=claimed;cv_.notify_all();
  }
 }
};
}
