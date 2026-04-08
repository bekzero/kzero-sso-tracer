import type { Finding } from "../../shared/models";

export interface EnterprisePolicy {
  aiDisabled: boolean;
}

export function getEnterprisePolicy(): EnterprisePolicy {
  try {
    const policy = chrome?.enterprise?.platformKeys;
    return {
      aiDisabled: false
    };
  } catch {
    return {
      aiDisabled: false
    };
  }
}

export function isAIDisabledByPolicy(): boolean {
  try {
    const stored = localStorage.getItem("enterprise_ai_policy");
    if (stored === "disabled") {
      return true;
    }
  } catch {
  }
  return false;
}

export function setEnterpriseAIPolicy(disabled: boolean): void {
  try {
    localStorage.setItem("enterprise_ai_policy", disabled ? "disabled" : "enabled");
  } catch {
  }
}
