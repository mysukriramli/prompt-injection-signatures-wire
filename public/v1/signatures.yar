/*
 * Prompt Injection & Agent Override YARA Ruleset
 * Generated UTC: 2026-11-24T00:23:48.974487+00:00
 */

rule INJ_BIDI_005 : bidi_override {
    meta:
        description = "Bidirectional text control overrides altering perceived token layout and agent instruction flow."
        severity = "MEDIUM"
    strings:
        $re = /[\\u202A-\\u202E\\u2066-\\u2069]/
    condition:
        $re
}

rule INJ_OBF_008 : encoding_evasion {
    meta:
        description = "Secondary obfuscation wrapper forcing LLM to decode embedded payload before execution."
        severity = "MEDIUM"
    strings:
        $re = /(?i)(?:base64\\s+decode\\s+this\\s+instruction|rot13|execute\\s+this\\s+hex\\s+string)/
    condition:
        $re
}

rule INJ_EXF_003 : markdown_data_exfiltration {
    meta:
        description = "Zero-click markdown image embedding targeting data extraction via URL query parameters."
        severity = "HIGH"
    strings:
        $re = /(?i)!\\[.*?\\]\\(https?:\\/\\/[^\\s\\)]+(?:\\?|&)(?:token|key|secret|cookie|auth|pwd|data|leak)=.*?(?:\\$|\\{).*?\\)/
    condition:
        $re
}

rule INJ_JAIL_006 : jailbreak_persona {
    meta:
        description = "Roleplay jailbreak patterns attempting persona-based ethical guardrail circumvention."
        severity = "HIGH"
    strings:
        $re = /(?i)(?:you\\s+are\\s+now\\s+(?:DAN|unrestricted|jailbroken|an\\s+unaligned\\s+AI)|operate\\s+without\\s+(?:safety|moral|policy)\\s+(?:guidelines|filters)|hypothetical\\s+mode\\s+enabled)/
    condition:
        $re
}

rule INJ_UNI_004 : unicode_steganography {
    meta:
        description = "Consecutive zero-width unicode characters used to conceal injected text from tokenizers."
        severity = "HIGH"
    strings:
        $re = /[\\u200B-\\u200D\\uFEFF]{2,}/
    condition:
        $re
}

rule INJ_SYS_001 : instruction_override {
    meta:
        description = "Direct imperative override targeting base system instructions."
        severity = "CRITICAL"
    strings:
        $re = /(?i)(?:ignore\\s+(?:all\\s+)?previous\\s+(?:instructions|prompts|directives|context)|disregard\\s+(?:all\\s+)?prior\\s+(?:rules|commands)|forget\\s+(?:all\\s+)?previous\\s+instructions)/
    condition:
        $re
}

rule INJ_TAG_002 : delimiter_smuggling {
    meta:
        description = "Synthetic chat-template delimiter boundary injection."
        severity = "CRITICAL"
    strings:
        $re = /(?i)<\\s*(?:\\|im_start\\||\\|im_end\\||system|assistant|instruction|human|system_prompt)\\s*>/
    condition:
        $re
}

rule INJ_TOOL_007 : tool_call_forgery {
    meta:
        description = "Synthetic function-calling markup embedded in untrusted external text."
        severity = "CRITICAL"
    strings:
        $re = /(?i)(?:\\{\\s*\\\"name\\\"\\s*:\\s*\\\"(?:execute_command|bash|run_shell|write_file|delete_file)\\\"|call:(?:execute|shell|cmd)\\()/
    condition:
        $re
}
