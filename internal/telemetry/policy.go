package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/log"
)

// EmitPolicyDecision emits an OTel LogRecord for a security-relevant policy
// evaluation decision such as firewall deny, admission block, or sandbox
// restrict. Routine "allow" decisions should generally not be emitted to
// avoid log noise; callers decide when a decision is noteworthy.
func (p *Provider) EmitPolicyDecision(
	domain, verdict, target, targetType, reason string,
	extra map[string]string,
) {
	if !p.LogsEnabled() {
		return
	}

	sevText, sevNum := policyVerdictSeverity(verdict)
	body := domain + " policy: " + verdict + " " + targetType + " " + target

	now := time.Now()
	rec := log.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(log.Severity(sevNum))
	rec.SetSeverityText(sevText)
	rec.SetBody(log.StringValue(body))

	attrs := []log.KeyValue{
		log.String("event.name", "policy.decision"),
		log.String("event.domain", "defenseclaw.policy"),
		log.String("defenseclaw.policy.domain", domain),
		log.String("defenseclaw.policy.verdict", verdict),
		log.String("defenseclaw.policy.target", target),
		log.String("defenseclaw.policy.target_type", targetType),
		log.String("defenseclaw.policy.reason", reason),
	}

	for k, v := range extra {
		if v != "" {
			attrs = append(attrs, log.String("defenseclaw.policy."+k, v))
		}
	}

	rec.AddAttributes(attrs...)
	p.logger.Emit(context.Background(), rec)
}

func policyVerdictSeverity(verdict string) (string, int) {
	switch verdict {
	case "blocked", "rejected", "deny", "block":
		return "WARN", 13
	case "failed":
		return "ERROR", 17
	default:
		return "INFO", 9
	}
}
