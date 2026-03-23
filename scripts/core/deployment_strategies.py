"""
Deployment Strategies for CrowdStrike Detection Rules

Handles multi-phase deployment patterns required by CrowdStrike API restrictions.
Different strategies are used based on the current and target rule states.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Callable, Optional
import logging
import time

logger = logging.getLogger(__name__)

# Maximum retries for 409 "rule is currently being updated" responses
MAX_409_RETRIES = 6
# Backoff schedule in seconds for 409 retries (total ~63s worst case)
RETRY_BACKOFF = [1, 2, 4, 8, 16, 32]


class DeploymentStrategy(ABC):
    """
    Abstract base class for detection rule deployment strategies.

    Each strategy handles a specific deployment scenario with potentially
    multiple phases to work around API restrictions.
    """

    def __init__(
        self,
        resource_id: str,
        template: Dict[str, Any],
        current_status: str,
        target_status: str,
        falcon_command: Callable,
        wait_for_status: Callable[[str, str, int], bool]
    ):
        """
        Initialize deployment strategy.

        Args:
            resource_id: ID of the rule to update
            template: New rule template data
            current_status: Current rule status (ACTIVE, STOPPED, INACTIVE, RUNNING)
            target_status: Target status from template (active, inactive)
            falcon_command: Callback to execute Falcon API commands
            wait_for_status: Callback to wait for status change
        """
        self.resource_id = resource_id
        self.template = template
        self.current_status = current_status.upper()
        self.target_status = target_status.lower()
        self.falcon_command = falcon_command
        self.wait_for_status = wait_for_status

    @abstractmethod
    def execute(self, prepare_patch_payload: Callable) -> Dict[str, Any]:
        """
        Execute the deployment strategy.

        Args:
            prepare_patch_payload: Callback to prepare PATCH payload from template

        Returns:
            API response from final operation

        Raises:
            RuntimeError: If deployment fails
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return human-readable name of this strategy"""
        pass

    def _patch_with_retry(self, payload: list, phase_label: str = "") -> Dict[str, Any]:
        """
        Execute a PATCH call with retry on 409 "rule is currently being updated".

        The CrowdStrike API returns 409 when a rule is in a transient state
        (e.g., still processing a previous update). This method retries with
        exponential backoff until the rule is ready.

        Args:
            payload: The PATCH payload (already wrapped in a list)
            phase_label: Human-readable label for logging (e.g., "Phase 2")

        Returns:
            API response on success

        Raises:
            RuntimeError: If all retries are exhausted or a non-409 error occurs
        """
        last_response = None
        for attempt in range(MAX_409_RETRIES + 1):
            response = self.falcon_command("entities_rules_patch_v1", body=payload)

            if response["status_code"] in (200, 201):
                return response

            # Check for 409 "currently being updated" - retry with backoff
            if response["status_code"] == 409:
                last_response = response
                errors = response.get("body", {}).get("errors", [])
                is_updating = any("currently being updated" in (e.get("message", "")) for e in errors)

                if is_updating and attempt < MAX_409_RETRIES:
                    wait_time = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                    logger.info(
                        f"{phase_label}Rule is still updating, retrying in {wait_time}s "
                        f"(attempt {attempt + 1}/{MAX_409_RETRIES})..."
                    )
                    time.sleep(wait_time)
                    continue

            # Non-retryable error
            return response

        # All retries exhausted
        return last_response


class SinglePhaseStrategy(DeploymentStrategy):
    """
    Standard single-phase deployment.

    Used when:
    - No status change
    - Status change without schedule conflicts
    - Simple attribute updates
    """

    def get_name(self) -> str:
        return "Single-phase deployment"

    def execute(self, prepare_patch_payload: Callable) -> Dict[str, Any]:
        """Execute single-phase update"""
        payload = prepare_patch_payload(self.template)
        payload['id'] = self.resource_id

        # Remove operation/schedule fields when rule is or will be STOPPED/INACTIVE
        # API restriction: "scheduled report can't be transitioned in state 'STOPPED'
        # and also update attributes 'schedule', 'start_on' or 'stop_on'"
        if (self.current_status in ['STOPPED', 'INACTIVE'] or
            self.target_status == 'inactive') and 'operation' in payload:
            logger.info(
                f"Removing operation fields for STOPPED/INACTIVE rule to avoid API conflict "
                f"(current: {self.current_status}, target: {self.target_status})"
            )
            del payload['operation']

        logger.debug(f"[DEBUG] Single-phase PATCH payload keys: {list(payload.keys())}")

        response = self._patch_with_retry([payload])

        if response["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Single-phase deployment failed for rule '{self.template['name']}': {response}"
            )

        return response


class TwoPhaseActivationStrategy(DeploymentStrategy):
    """
    Two-phase activation deployment.

    Used when:
    - Activating a STOPPED/INACTIVE rule that has schedule changes

    Process:
    1. Activate the rule (without schedule)
    2. Wait for status to become ACTIVE
    3. Update schedule and other attributes
    """

    def get_name(self) -> str:
        return "Two-phase activation (activate → update schedule)"

    def execute(self, prepare_patch_payload: Callable) -> Dict[str, Any]:
        """Execute two-phase activation"""
        logger.info(f"Using {self.get_name()}")

        # Phase 1: Activate the rule only (no schedule changes)
        phase1_payload = {
            "id": self.resource_id,
            "status": "active"
        }

        logger.info("Phase 1: Activating rule...")
        response1 = self._patch_with_retry([phase1_payload], phase_label="Phase 1: ")

        if response1["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Phase 1 failed: Could not activate rule '{self.template['name']}': {response1}"
            )

        logger.info("Phase 1 complete: Rule activated")

        # Wait for rule to reach active status with exponential backoff polling
        if not self.wait_for_status(self.resource_id, 'active', 30):
            logger.warning("Rule may not be fully active yet, continuing with Phase 2...")

        # Phase 2: Update schedule and other attributes
        phase2_payload = prepare_patch_payload(self.template)
        phase2_payload['id'] = self.resource_id
        phase2_payload['status'] = 'active'  # Maintain active status

        logger.debug(f"[DEBUG] Phase 2 PATCH payload keys: {list(phase2_payload.keys())}")

        logger.info("Phase 2: Updating schedule and attributes...")
        response = self._patch_with_retry([phase2_payload], phase_label="Phase 2: ")

        if response["status_code"] not in (200, 201):
            logger.debug(f"[DEBUG] Phase 2 error response: {response}")
            raise RuntimeError(
                f"Phase 2 failed: Could not update schedule for '{self.template['name']}': {response}"
            )

        logger.info("Two-phase activation complete")
        return response


class TwoPhaseDeactivationStrategy(DeploymentStrategy):
    """
    Two-phase deactivation deployment.

    Used when:
    - Deactivating an ACTIVE/RUNNING rule

    Process:
    1. Update all attributes except status (while still active)
    2. Deactivate the rule

    Note: Schedule/operation fields are removed from Phase 1 to avoid conflicts
    """

    def get_name(self) -> str:
        return "Two-phase deactivation (update attrs → deactivate)"

    def execute(self, prepare_patch_payload: Callable) -> Dict[str, Any]:
        """Execute two-phase deactivation"""
        logger.info(f"Using {self.get_name()}")

        # Phase 1: Update all attributes EXCEPT status and operation/schedule
        phase1_payload = prepare_patch_payload(self.template)
        phase1_payload['id'] = self.resource_id
        phase1_payload['status'] = self.current_status.lower()  # Keep current status

        # Remove operation fields to avoid API conflict
        if 'operation' in phase1_payload:
            del phase1_payload['operation']

        logger.info("Phase 1: Updating attributes (excluding schedule)...")
        response1 = self._patch_with_retry([phase1_payload], phase_label="Phase 1: ")

        if response1["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Phase 1 failed: Could not update rule attributes '{self.template['name']}': {response1}"
            )

        logger.info("Phase 1 complete: Attributes updated")

        # Phase 2: Deactivate the rule
        phase2_payload = {
            "id": self.resource_id,
            "status": "inactive"
        }

        logger.info("Phase 2: Deactivating rule...")
        response = self._patch_with_retry([phase2_payload], phase_label="Phase 2: ")

        if response["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Phase 2 failed: Could not deactivate rule '{self.template['name']}': {response}"
            )

        logger.info("Two-phase deactivation complete")
        return response


class ThreePhaseStoppedScheduleStrategy(DeploymentStrategy):
    """
    Three-phase deployment for stopped rules with schedule changes.

    Used when:
    - Rule is currently STOPPED/INACTIVE
    - Target status is also STOPPED/INACTIVE (staying stopped)
    - Template includes schedule changes

    Process:
    1. Temporarily activate the rule (without schedule)
    2. Update schedule and attributes while active
    3. Deactivate back to target status

    This is necessary because the API won't allow schedule updates while stopped.
    """

    def get_name(self) -> str:
        return "Three-phase stopped schedule (activate → update schedule → deactivate)"

    def execute(self, prepare_patch_payload: Callable) -> Dict[str, Any]:
        """Execute three-phase deployment"""
        logger.info(f"Using {self.get_name()}")
        logger.info("(Required because API won't allow schedule updates while rule is stopped)")

        # Phase 1: Temporarily activate the rule (no schedule)
        phase1_payload = {
            "id": self.resource_id,
            "status": "active"
        }

        logger.info("Phase 1: Temporarily activating rule...")
        response1 = self._patch_with_retry([phase1_payload], phase_label="Phase 1: ")

        if response1["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Phase 1 failed: Could not temporarily activate rule '{self.template['name']}': {response1}"
            )

        logger.info("Phase 1 complete: Rule temporarily activated")

        # Wait for rule to reach active status
        if not self.wait_for_status(self.resource_id, 'active', 30):
            logger.warning("Rule may not be fully active yet, continuing with Phase 2...")

        # Phase 2: Update schedule and other attributes while active
        phase2_payload = prepare_patch_payload(self.template)
        phase2_payload['id'] = self.resource_id
        phase2_payload['status'] = 'active'  # Keep active for now

        logger.info("Phase 2: Updating schedule and attributes (while active)...")
        response2 = self._patch_with_retry([phase2_payload], phase_label="Phase 2: ")

        if response2["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Phase 2 failed: Could not update schedule for '{self.template['name']}': {response2}"
            )

        logger.info("Phase 2 complete: Schedule and attributes updated")

        # Wait briefly for updates to settle
        if not self.wait_for_status(self.resource_id, 'active', 10):
            logger.warning("Rule may not be stable yet, continuing with Phase 3...")

        # Phase 3: Deactivate back to target status
        phase3_payload = {
            "id": self.resource_id,
            "status": self.target_status  # inactive or stopped
        }

        logger.info(f"Phase 3: Deactivating rule back to '{self.target_status}'...")
        response = self._patch_with_retry([phase3_payload], phase_label="Phase 3: ")

        if response["status_code"] not in (200, 201):
            raise RuntimeError(
                f"Phase 3 failed: Could not deactivate rule '{self.template['name']}': {response}"
            )

        logger.info("Three-phase deployment complete")
        return response


class DeploymentStrategyFactory:
    """
    Factory to select appropriate deployment strategy based on rule state.

    Analyzes current status, target status, and template changes to determine
    which deployment pattern is needed.
    """

    @staticmethod
    def create_strategy(
        resource_id: str,
        template: Dict[str, Any],
        current_status: str,
        falcon_command: Callable,
        wait_for_status: Callable
    ) -> DeploymentStrategy:
        """
        Create appropriate deployment strategy.

        Args:
            resource_id: ID of the rule to update
            template: New rule template data
            current_status: Current rule status (ACTIVE, STOPPED, INACTIVE, RUNNING)
            falcon_command: Callback to execute Falcon API commands
            wait_for_status: Callback to wait for status change

        Returns:
            DeploymentStrategy instance
        """
        target_status = template.get('status', 'active').lower()
        current_normalized = current_status.upper()

        # Check if there are schedule changes
        has_schedule_changes = (
            'operation' in template and
            'schedule' in template.get('operation', {})
        )

        # Determine state transitions
        is_activating = current_normalized in ['STOPPED', 'INACTIVE'] and target_status == 'active'
        is_deactivating = current_normalized in ['ACTIVE', 'RUNNING'] and target_status == 'inactive'
        is_staying_stopped = (
            current_normalized in ['STOPPED', 'INACTIVE'] and
            target_status != 'active'
        )

        # Select strategy based on conditions
        if is_staying_stopped and has_schedule_changes:
            # Three-phase: activate → update schedule → deactivate back
            return ThreePhaseStoppedScheduleStrategy(
                resource_id, template, current_status, target_status,
                falcon_command, wait_for_status
            )

        elif is_activating and has_schedule_changes:
            # Two-phase activation: activate → update schedule
            return TwoPhaseActivationStrategy(
                resource_id, template, current_status, target_status,
                falcon_command, wait_for_status
            )

        elif is_deactivating:
            # Two-phase deactivation: update attrs → deactivate
            return TwoPhaseDeactivationStrategy(
                resource_id, template, current_status, target_status,
                falcon_command, wait_for_status
            )

        else:
            # Standard single-phase deployment
            return SinglePhaseStrategy(
                resource_id, template, current_status, target_status,
                falcon_command, wait_for_status
            )
