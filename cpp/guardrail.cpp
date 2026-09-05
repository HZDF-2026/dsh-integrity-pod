// guardrail.cpp — see guardrail.h. Mirrors plugins/dsh-integrity-guardrail/index.js.
#include "guardrail.h"

#include "jsjson.h"
#include "jsre.h"
#include "sha256.h"
#include "util.h"

#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

namespace dship {

namespace {

struct PatternEntry {
    std::string id;
    std::unique_ptr<JsRegexp> pattern;
};

struct DenySpec {
    const char* id;
    const char* source;
    const char* flags;
};

const DenySpec DEFAULT_DENY_PATTERNS[] = {
    {"rm-root", "\\brm\\b[^|;&]*\\s(\\/|~|\\.|\\*|\\$HOME)(\\s|$)", ""},
    {"mkfs", "\\bmkfs(\\.[a-z0-9]+)?\\b", "i"},
    {"dd-raw-disk", "\\bdd\\b[^|;&]*\\bof=\\/dev\\/(sd|nvme|disk|hd)", "i"},
    {"pipe-to-shell",
     "\\b(curl|wget|iwr|invoke-webrequest)\\b[^|;&]*\\|\\s*(sudo\\s+)?(sh|bash|zsh|dash|ksh|"
     "pwsh|powershell|cmd)(\\.exe)?(\\s|$)",
     "i"},
    {"sudo", "\\bsudo\\s+\\S", ""},
    {"win-rd-s", "\\b(rd|rmdir)\\s+\\/s\\b", "i"},
    {"win-del-s", "\\bdel\\s+\\/[sq]\\b", "i"},
    {"win-format", "\\bformat\\s+[c-z]:", "i"},
    {"win-remove-item-drive",
     "\\bremove-item\\b(?=[^|;&]*\\b-recurse\\b)(?=[^|;&]*\\b-force\\b)(?=[^|;&]*[c-z]:[\\\\/])",
     "i"},
    {"shutdown", "\\b(shutdown|poweroff|reboot|halt)\\b(?=[\\s/]|$)", "i"},
    {"env-file", "\\.env(\\.[a-z0-9_-]+)?(?=[\\\\/\"'\\s:]|$)", ""},
    {"ssh-cred-file",
     "(^|[\\\\/\"'\\s=:,])(id_rsa|id_ed25519|id_ecdsa|authorized_keys|\\.netrc|\\.npmrc|"
     "\\.aws.{0,2}credentials)([\\\\/\"'\\s:]|$)",
     ""},
    {"git-force-main",
     "\\bgit\\s+push\\b(?=[^|;&]*(--force(-with-lease)?\\b|-f\\b))(?=[^|;&]*\\b(main|master)\\b)",
     "i"},
    {"chmod-root", "\\bchmod\\s+(-[a-z]+\\s+)*777\\s+\\/(\\s|$)", ""},
    {"etc-passwd-write",
     "\\b(cp|mv|tee|sed)\\b[^|;&]*\\/etc\\/(passwd|shadow|sudoers)\\b|>\\s*\\/etc\\/"
     "(passwd|shadow|sudoers)\\b",
     ""},
};

std::string jsTrim(const std::string& s) {
    size_t b = 0, e = s.size();
    auto isWs = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    while (b < e && isWs(s[b])) b++;
    while (e > b && isWs(s[e - 1])) e--;
    return s.substr(b, e - b);
}

// escapeRe: [.*+?^${}()|[\]\\] each gain a backslash prefix.
std::string escapeRe(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text) {
        if (c == '.' || c == '*' || c == '+' || c == '?' || c == '^' || c == '$' || c == '{' ||
            c == '}' || c == '(' || c == ')' || c == '|' || c == '[' || c == ']' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    return out;
}

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (size_t i = 0; i < text.size(); i++) {
        if (text[i] == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            lines.push_back(cur);
            cur.clear();
        } else {
            cur += text[i];
        }
    }
    lines.push_back(cur);
    return lines;
}

// subjectTexts(exec): the string form plus every direct string/object value.
// Object.values() only yields strings and typeof-object values — numbers,
// booleans and nulls never become screening subjects.
std::vector<std::string> subjectTexts(const Json& args) {
    std::vector<std::string> texts;
    if (args.isStr()) {
        texts.push_back(args.str);
    } else if (!args.isNull()) {
        texts.push_back(args.dump());
        if (args.isArr()) {
            for (const Json& v : args.arr) {
                if (v.isStr()) texts.push_back(v.str);
                else if (v.isArr() || v.isObj()) texts.push_back(v.dump());
            }
        } else if (args.isObj()) {
            for (const auto& kv : args.obj) {
                if (kv.second.isStr()) texts.push_back(kv.second.str);
                else if (kv.second.isArr() || kv.second.isObj()) texts.push_back(kv.second.dump());
            }
        }
    }
    return texts;
}

struct Violation {
    std::string id;
    std::string reason;
};

Violation findDeny(const std::string& name, const std::vector<std::string>& texts,
                  const std::vector<PatternEntry>& denyPatterns) {
    for (const PatternEntry& entry : denyPatterns) {
        for (const std::string& text : texts) {
            if (entry.pattern->test(text)) {
                return {entry.id, "tool \"" + name + "\" matches deny pattern \"" + entry.id + "\""};
            }
        }
    }
    return {"", ""};
}

struct CompiledConfig {
    std::string mode;
    std::vector<PatternEntry> denyPatterns;
    std::vector<PatternEntry> allowPatterns;
    std::string integrityStoreDir;
    bool protectIntegrityStores = true;
    bool auditLog = true;
    std::string auditPath;
};

void compilePatternsInto(std::vector<PatternEntry>& out, const std::vector<std::string>& sources,
                         const std::string& field, const std::string& idPrefix) {
    for (size_t i = 0; i < sources.size(); i++) {
        if (jsTrim(sources[i]).empty()) {
            throw std::runtime_error("dsh-integrity-guardrail: " + field +
                                     " entries must be non-empty regex source strings.");
        }
        try {
            out.push_back({idPrefix + "-" + std::to_string(i + 1),
                           JsRegexp::compile(sources[i], "")});
        } catch (const std::runtime_error& error) {
            throw std::runtime_error("dsh-integrity-guardrail: invalid regex in " + idPrefix + "[" +
                                     std::to_string(i) + "] (" + sources[i] + "): " + error.what());
        }
    }
}

CompiledConfig compileConfig(const GuardrailConfig& raw) {
    CompiledConfig cfg;
    cfg.mode = raw.mode.empty() ? "enforce" : raw.mode;
    if (cfg.mode != "enforce" && cfg.mode != "audit") {
        throw std::runtime_error("dsh-integrity-guardrail: mode must be \"enforce\" or \"audit\", got " +
                                 Json::string(cfg.mode).dump() + ".");
    }
    for (const DenySpec& spec : DEFAULT_DENY_PATTERNS) {
        cfg.denyPatterns.push_back({spec.id, JsRegexp::compile(spec.source, spec.flags)});
    }
    compilePatternsInto(cfg.denyPatterns, raw.extraDenyPatterns, "extraDenyPatterns", "extraDeny");
    compilePatternsInto(cfg.allowPatterns, raw.allowPatterns, "allowPatterns", "allow");
    cfg.integrityStoreDir = raw.integrityStoreDir.empty() ? ".integrity" : raw.integrityStoreDir;
    cfg.protectIntegrityStores = raw.protectIntegrityStores;
    cfg.auditLog = raw.auditLog;
    cfg.auditPath =
        pathResolve(raw.auditPath.empty() ? ".integrity/tool-audit.jsonl" : raw.auditPath);
    return cfg;
}

Violation integrityStoreViolation(const std::string& name, const std::vector<std::string>& texts,
                                  const std::string& integrityStoreDir) {
    bool dirHit = false;
    for (const std::string& text : texts) {
        if (text.find(integrityStoreDir) != std::string::npos) {
            dirHit = true;
            break;
        }
    }
    if (!dirHit) return {"", ""};
    if (JsRegexp::compile("^(write|edit|delete|remove|move|rename|save|patch|truncate)$", "")
            ->test(name)) {
        return {"integrity-store-write",
                "tool \"" + name + "\" targets the integrity store \"" + integrityStoreDir +
                    "\"; only integrity tools may write there"};
    }
    if (JsRegexp::compile("bash|shell|exec|run|terminal|command", "i")->test(name)) {
        std::unique_ptr<JsRegexp> dirRe =
            JsRegexp::compile(escapeRe(integrityStoreDir), "");
        std::unique_ptr<JsRegexp> mutationRe = JsRegexp::compile(
            "\\b(rm|rmdir|mv|cp|truncate|tee|sed|chmod|del|rd)\\b[^|;&]{0,400}", "");
        std::unique_ptr<JsRegexp> redirectRe =
            JsRegexp::compile(">{1,2}\\s*\\S*" + escapeRe(integrityStoreDir), "");
        for (const std::string& text : texts) {
            if ((mutationRe->test(text) && dirRe->test(text)) || redirectRe->test(text)) {
                return {"integrity-store-write",
                        "command writes into the integrity store \"" + integrityStoreDir +
                            "\"; only integrity tools may write there"};
            }
        }
    }
    return {"", ""};
}

class AuditLog {
public:
    explicit AuditLog(std::string auditPath) : path_(std::move(auditPath)) {}

    void init() {
        if (initialized_) return;
        initialized_ = true;
        std::ifstream in(path_, std::ios::binary);
        if (!in) return;
        std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        for (const std::string& line : splitLines(text)) {
            if (jsTrim(line).empty()) continue;
            Json parsed;
            if (!Json::parse(line, parsed)) continue;
            const Json* h = parsed.get("hash");
            if (h && h->isStr()) {
                lastHash_ = h->str;
                count_++;
            }
        }
    }

    void append(const std::string& kind, const std::string& name, bool isError,
                const std::string& callId, const std::string& detail) {
        init();
        std::string at = nowIso();
        Json callIdJ = callId.empty() ? Json::null() : Json::string(callId);
        Json detailJ = detail.empty() ? Json::null() : Json::string(detail);
        Json prevHashJ = lastHash_.empty() ? Json::null() : Json::string(lastHash_);

        Json record = Json::object();
        record.set("at", Json::string(at));
        record.set("kind", Json::string(kind));
        record.set("name", Json::string(name));
        record.set("isError", Json::boolean(isError));
        record.set("callId", callIdJ);
        record.set("detail", detailJ);
        record.set("prevHash", prevHashJ);
        std::string hash;
        {
            Json payload = Json::object();
            payload.set("at", Json::string(at));
            payload.set("kind", Json::string(kind));
            payload.set("name", Json::string(name));
            payload.set("isError", Json::boolean(isError));
            payload.set("callId", callIdJ);
            payload.set("detail", detailJ);
            payload.set("prevHash", prevHashJ);
            hash = sha256Hex(payload.dump());
        }
        record.set("hash", Json::string(hash));

        mkdirRecursive(pathDirname(path_));
        appendFileBytes(path_, record.dump() + "\n");
        lastHash_ = hash;
        count_++;
    }

    size_t count() const { return count_; }
    const std::string& lastHash() const { return lastHash_; }
    const std::string& path() const { return path_; }

private:
    std::string path_;
    std::string lastHash_;
    size_t count_ = 0;
    bool initialized_ = false;
};

Json parseArguments(const std::string& argumentsJson) {
    Json args = Json::null();
    if (argumentsJson.empty()) return args;
    if (!Json::parse(argumentsJson, args)) {
        throw std::runtime_error("arguments must be valid JSON.");
    }
    return args;
}

}  // namespace

std::string guardrailCheck(const std::string& toolName, const std::string& callId,
                           const std::string& argumentsJson, const GuardrailConfig& config) {
    CompiledConfig cfg = compileConfig(config);
    std::vector<std::string> texts = subjectTexts(parseArguments(argumentsJson));
    if (texts.empty()) return "{\"kind\":\"allow\"}";

    bool allowHit = false;
    for (const PatternEntry& entry : cfg.allowPatterns) {
        for (const std::string& text : texts) {
            if (entry.pattern->test(text)) {
                allowHit = true;
                break;
            }
        }
        if (allowHit) break;
    }

    if (!allowHit) {
        Violation violation = findDeny(toolName, texts, cfg.denyPatterns);
        if (violation.reason.empty() && cfg.protectIntegrityStores) {
            violation = integrityStoreViolation(toolName, texts, cfg.integrityStoreDir);
        }
        if (!violation.reason.empty()) {
            // Node's audit.append swallows every failure; denial must never
            // depend on the audit write.
            try {
                AuditLog audit(cfg.auditPath);
                audit.append(cfg.mode == "enforce" ? "deny" : "would-deny",
                             toolName.empty() ? "unknown" : toolName, false, callId,
                             "[" + violation.id + "] " + violation.reason);
            } catch (...) {
            }
            if (cfg.mode == "enforce") {
                Json out = Json::object();
                out.set("kind", Json::string("deny"));
                out.set("reason",
                        Json::string("Denied by dsh-integrity-guardrail [" + violation.id + "]: " +
                                     violation.reason +
                                     ". Fix the call, or add an allowPattern if this is "
                                     "intentional."));
                return out.dump();
            }
        }
    }

    Json out = Json::object();
    out.set("kind", Json::string("allow"));
    return out.dump();
}

std::string guardrailLogResult(const std::string& toolName, bool isError, const std::string& callId,
                               const GuardrailConfig& config) {
    CompiledConfig cfg = compileConfig(config);
    bool appended = false;
    if (cfg.auditLog) {
        try {
            AuditLog audit(cfg.auditPath);
            audit.append("tool_result", toolName.empty() ? "unknown" : toolName, isError, callId,
                         "");
            appended = true;
        } catch (...) {
        }
    }
    Json out = Json::object();
    out.set("appended", Json::boolean(appended));
    return out.dump();
}

std::string guardrailStatus(const GuardrailConfig& config) {
    CompiledConfig cfg = compileConfig(config);
    AuditLog audit(cfg.auditPath);
    audit.init();

    Json out = Json::object();
    out.set("plugin", Json::string("dsh-integrity-guardrail"));
    out.set("mode", Json::string(cfg.mode));
    {
        Json deny = Json::array();
        for (const PatternEntry& entry : cfg.denyPatterns) deny.push(Json::string(entry.id));
        out.set("denyPatterns", std::move(deny));
    }
    {
        Json allow = Json::array();
        for (const PatternEntry& entry : cfg.allowPatterns) allow.push(Json::string(entry.id));
        out.set("allowPatterns", std::move(allow));
    }
    out.set("protectIntegrityStores", Json::boolean(cfg.protectIntegrityStores));
    out.set("integrityStoreDir", Json::string(cfg.integrityStoreDir));
    out.set("auditLog", Json::boolean(cfg.auditLog));
    out.set("auditPath", Json::string(audit.path()));
    out.set("auditRecords", Json::number(static_cast<double>(audit.count())));
    out.set("lastAuditHash",
            audit.lastHash().empty() ? Json::null() : Json::string(audit.lastHash().substr(0, 12)));
    return out.dump();
}

}  // namespace dship
