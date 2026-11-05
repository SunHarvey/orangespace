// Non-destructive regression: a failed predicate must never carry success.
#define wmain cross_user_fixture_entry_not_run
#include "cross_user_fixture.cpp"
#undef wmain
#include <iostream>
int main() {
    SetLastError(ERROR_SUCCESS);
    try {
        require(false, "injected_zero_last_error");
        std::cerr << "FAIL: predicate failure was accepted\n";
        return 1;
    } catch (Failure failure) {
        if (failure.error == ERROR_SUCCESS) {
            std::cerr << "FAIL: failed predicate carried zero error\n";
            return 1;
        }
    }
    std::cout << "PASS: failed predicate cannot report success\n";
}
