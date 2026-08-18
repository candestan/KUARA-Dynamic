#include "kuara_internal.h"

namespace kuara
{
const char* EngineId()
{
    return "com.candestan.kuara";
}

const char* EngineVersion()
{
    return "0.1.0";
}

const char* EngineAuthor()
{
    return "candestan";
}

const char* BrandImageUrl()
{
    return "";
}

bool Explain(const CompiledRuleSet& compiled, const ScanFacts& facts, const std::string& rule_id, std::vector<Diagnostic>* out_trace)
{
    out_trace->clear();
    for (const CompiledRule& cr : compiled.rules)
    {
        if (cr.rule.id == rule_id)
            return ExplainRule(cr, facts, out_trace);
    }
    out_trace->push_back({rule_id, "rule not found", true});
    return false;
}
} // namespace kuara

