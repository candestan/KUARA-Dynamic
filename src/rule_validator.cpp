#include "kuara_internal.h"

#include <unordered_set>

namespace kuara
{
bool ValidateRuleSet(const RuleSet& rules, std::vector<Diagnostic>* out_diags)
{
    std::unordered_set<std::string> ids;
    if (rules.rules.empty())
    {
        out_diags->push_back({"ruleset", "ruleset is empty", true});
        return false;
    }
    for (const Rule& r : rules.rules)
    {
        if (r.schema_version != 1)
            out_diags->push_back({r.id, "schema_version must be 1", true});
        if (r.id.size() < 3 || r.id.size() > 80)
            out_diags->push_back({r.id, "id length must be 3..80", true});
        if (!ids.insert(r.id).second)
            out_diags->push_back({r.id, "duplicate rule id", true});
    }
    for (const Diagnostic& d : *out_diags)
    {
        if (d.error)
            return false;
    }
    return true;
}

bool CompileRuleSet(const RuleSet& rules, CompiledRuleSet* out_compiled, std::vector<Diagnostic>* out_diags)
{
    out_compiled->rules.clear();
    if (!ValidateRuleSet(rules, out_diags))
        return false;
    for (const Rule& r : rules.rules)
        out_compiled->rules.push_back(CompiledRule{r});
    return true;
}
} // namespace kuara

