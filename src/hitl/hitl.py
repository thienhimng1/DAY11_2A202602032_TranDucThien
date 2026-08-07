"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 11: Confidence Router
  TODO 12: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 11: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # 1. High-risk actions ALWAYS escalate regardless of confidence
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # 2. Confidence-based routing
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# TODO 12: Design 3 HITL decision points + a review lifecycle
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
# - approval_path: What approve/reject/timeout decision is recorded?
# - audit_fields: Which correlation ID, intent and proposed action/diff are logged?
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large Money Transfer Approval",
        "trigger": "transfer_money action with amount >= 50,000,000 VND or cross-border destination",
        "hitl_model": "human-in-the-loop",
        "context_needed": (
            "Transaction details: sender account, recipient account, amount, currency, "
            "destination bank. Previous transaction history for this sender. "
            "Risk score from fraud detection model."
        ),
        "example": (
            "Customer requests transfer of 100,000,000 VND to an account at a foreign bank. "
            "Agent drafts the transfer but pauses for human approval before execution."
        ),
        "approval_path": (
            "APPROVE: Transfer proceeds with correlation ID logged. "
            "REJECT: Transfer cancelled, customer notified with reason. "
            "TIMEOUT (5 min): Auto-reject, fail closed. Customer asked to retry via branch."
        ),
        "audit_fields": (
            "correlation_id (UUID), intent=transfer_money, proposed_amount, "
            "proposed_destination, risk_score, reviewer_id, decision (approve/reject/timeout), "
            "decision_timestamp, review_duration_ms"
        ),
    },
    {
        "id": 2,
        "name": "Account Closure Request",
        "trigger": "close_account action requested by any user through the chatbot",
        "hitl_model": "human-in-the-loop",
        "context_needed": (
            "Account holder identity verification status, current balance, "
            "pending transactions, linked services (auto-pay, cards), "
            "recent login history (was session hijacked?)."
        ),
        "example": (
            "Customer says 'I want to close my savings account ending in 4521'. "
            "Agent validates identity, shows summary of impact (pending deposits, linked cards), "
            "then queues for human reviewer who confirms the closure is intentional."
        ),
        "approval_path": (
            "APPROVE: Account scheduled for closure after 7-day cooling period. "
            "REJECT: Closure denied, escalate to branch manager if customer insists. "
            "TIMEOUT (10 min): Auto-reject. Customer directed to visit branch in person."
        ),
        "audit_fields": (
            "correlation_id (UUID), intent=close_account, account_id, "
            "identity_verified (bool), balance_at_request, reviewer_id, "
            "decision, decision_timestamp, cooling_period_end"
        ),
    },
    {
        "id": 3,
        "name": "Personal Information Update",
        "trigger": "update_personal_info action (email, phone, address, or name change)",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": (
            "Current vs proposed personal info diff, identity verification score, "
            "device fingerprint (known device?), time since last info change, "
            "whether change was preceded by a password reset."
        ),
        "example": (
            "Customer requests to change registered phone number from 0901234567 to 0987654321. "
            "Automated system flags this because the request came from a new device. "
            "Human reviewer checks if OTP was sent to the OLD number for confirmation."
        ),
        "approval_path": (
            "APPROVE: Info updated, confirmation sent to both old and new contact. "
            "REJECT: Change denied, security alert sent to original contact. "
            "TIMEOUT (3 min): Auto-reject, fail closed. Customer asked to verify via branch."
        ),
        "audit_fields": (
            "correlation_id (UUID), intent=update_personal_info, field_changed, "
            "old_value_hash, new_value_hash, device_known (bool), "
            "reviewer_id, decision, decision_timestamp"
        ),
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
