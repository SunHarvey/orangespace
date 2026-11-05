"""Generate exact backend method fixtures; injected policy, NOT native acceptance.

No helper, SCM, WinHTTP or runtime is executed by this generator or its fixture.
The source bodies are extracted on every dependent build, never cached snapshots.
"""
from pathlib import Path
import argparse
import re


def block(source, signature):
    if source.count(signature) != 1:
        raise ValueError("backend fixture signature drift")
    begin = source.index(signature)
    left = source.index("{", begin)
    # Ignore braces in ordinary C++ string/character literals and comments.
    # Raw literals are not used in these production methods; reject drift rather
    # than silently extracting a different body.
    tokens = re.compile(r'//[^\n]*|/\*.*?\*/|R"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for match in tokens.finditer(source, left):
        token = match.group()
        if token == 'R"':
            raise ValueError("unsupported raw literal in backend fixture extraction")
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                return source[begin:match.end()]
    raise ValueError("unterminated backend fixture method")


def generate(source):
    members = [line.strip() for line in source.splitlines() if " realms_;" in line]
    if len(members) != 1:
        raise ValueError("backend realm declaration drift")
    parts = [block(source, "struct Realm {") + ";", members[0]]
    for signature in (
        "void release(std::string_view realm) noexcept override",
        "void reserve(std::string_view realm,",
        "std::shared_ptr<Realm> reserved(",
        "Proof start(std::string_view realm,",
        "void close(std::string_view realm,",
        "void renew(std::string_view realm,",
        "bool alive(std::string_view realm,",
        "bool diagnose(std::string_view realm,",
    ):
        method = block(source, signature)
        left = method.index("{")
        parts.append(method[:left].replace(" override", "") + method[left:])
    actual = block(source, "std::string call(void* runtime_,")
    for signature in ("struct OrdinaryInvalid {", "bool confirm_absent("):
        if signature in source:
            item = block(source, signature)
            actual += "\n" + item + (";" if signature.startswith("struct") else "")
    head = '''// Generated from exact production methods; injected OS/FFI seams.
struct ExtractedBackend {
  std::mutex mutex_; bool poisoned_{}; std::unique_ptr<PinnedFile> helper_;
  bool prototype_mixed_{};
  // Legacy fixtures never enable the prototype constructor. Keep this explicit
  // compile seam here rather than inventing a runtime implementation.
  void* os_runtime_new_with_local_proxy_v1(const std::uint8_t*,std::size_t,unsigned,const std::uint8_t*,std::size_t,unsigned) {throw std::runtime_error("unexpected prototype constructor");}
  // Existing budget fixtures inject default public trust; private CA fixture
  // replaces this seam with the exact production catalog accessor body.
  std::shared_ptr<const std::string> trusted_ca_for_node(std::string_view) {return {};}
  std::function<void()> on_call;
  std::vector<std::string> requests;
  std::string call(void*, std::string_view request) {
    ++calls; requests.emplace_back(request); if(on_call) on_call();
    return R"({"ok":true,"process_started":true,"tunnel_authenticated":true,"forwarding_verified":true,"exited":[]})";
  }
'''
    begin = head.index('  std::string call(')
    head = head[:begin] + '#ifdef ORANGESPACE_TEST_ACTUAL_CALL\n' + actual + '\n#else\n' + head[begin:] + '#endif\n'
    return head + "\n".join(parts) + "\n};\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = generate(args.source.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result, encoding="utf-8")


if __name__ == "__main__":
    main()
