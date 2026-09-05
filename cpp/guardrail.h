// guardrail.h — dsh-integrity-guardrail: deny-pattern tool-call screening
// plus a hash-chained tool audit log.
#ifndef dship_GUARDRAIL_H
#define dship_GUARDRAIL_H

#include <string>
#include <vector>

namespace dship {

struct GuardrailConfig {
    std::string mode = "enforce";                 // "enforce" or "audit"
    std::vector<std::string> extraDenyPatterns;    // regex sources
    std::vector<std::string> allowPatterns;        // regex sources
    std::string integrityStoreDir = ".integrity";
    bool protectIntegrityStores = true;
    bool auditLog = true;
    std::string auditPath;    // empty -> ".integrity/tool-audit.jsonl" (resolved)
};

// Screening of a single tool call. argumentsJson is the exec.arguments value as
// JSON (string, object, array, number, boolean or null; empty -> null).
// Returns {"kind":"deny","reason":...} when the call is denied, else
// {"kind":"allow"}. Throws std::runtime_error with the plugin's message on
// invalid configuration or malformed arguments JSON.
std::string guardrailCheck(const std::string& toolName, const std::string& callId,
                           const std::string& argumentsJson, const GuardrailConfig& config);

// tools/result hook: append a tool_result event to the audit log (only when
// config.auditLog). Returns {"appended":true|false}.
std::string guardrailLogResult(const std::string& toolName, bool isError, const std::string& callId,
                               const GuardrailConfig& config);

// guardrail_status tool output (exact key order). Unlike the Node plugin's
// in-memory counter, the audit statistics are read from disk: every CLI
// invocation is a fresh session whose state IS the audit file.
std::string guardrailStatus(const GuardrailConfig& config);

}  // namespace dship

#endif  // dship_GUARDRAIL_H
