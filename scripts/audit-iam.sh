#!/usr/bin/env bash
# Read-only IAM and account security audit for AWS CLI.
# Usage: ./audit-iam.sh [--profile PROFILE] [--region REGION] [--output-dir DIR]
set -euo pipefail
export AWS_PAGER=""

PROFILE=""
REGION="${AWS_REGION:-eu-west-1}"
OUTPUT_DIR=""
AWS_CLI="${AWS_CLI:-aws}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h | --help)
      echo "Usage: $0 [--profile PROFILE] [--region REGION] [--output-dir DIR]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    if [[ "$1" == "aws" ]]; then
      echo "Install AWS CLI v2 and ensure it is on PATH, or set AWS_CLI to the aws binary path." >&2
    fi
    exit 127
  fi
}

require_command "$AWS_CLI"

AWS=("$AWS_CLI" --region "$REGION")
if [[ -n "$PROFILE" ]]; then
  AWS+=(--profile "$PROFILE")
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

section() {
  printf '\n===== %s =====\n' "$1"
}

run_audit() {
  section "Caller identity"
  "${AWS[@]}" sts get-caller-identity

  section "Organization"
  if ! "${AWS[@]}" organizations describe-organization 2>/dev/null; then
    echo "Organization: not enabled or not accessible from this principal."
  fi

  if ! "${AWS[@]}" organizations list-accounts 2>/dev/null; then
    echo "Organization accounts: not available."
  fi

  section "IAM Identity Center"
  if ! "${AWS[@]}" sso-admin list-instances 2>/dev/null; then
    echo "Identity Center: not enabled or not accessible."
  fi

  instance_arn="$("${AWS[@]}" sso-admin list-instances --query 'Instances[0].InstanceArn' --output text 2>/dev/null || true)"
  identity_store_id="$("${AWS[@]}" sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text 2>/dev/null || true)"
  if [[ -n "$instance_arn" && "$instance_arn" != "None" ]]; then
    "${AWS[@]}" sso-admin list-permission-sets --instance-arn "$instance_arn" || true
    if [[ -n "$identity_store_id" && "$identity_store_id" != "None" ]]; then
      "${AWS[@]}" identitystore list-users --identity-store-id "$identity_store_id" || true
      "${AWS[@]}" identitystore list-groups --identity-store-id "$identity_store_id" || true
    fi
  fi

  section "IAM users"
  "${AWS[@]}" iam list-users

  section "IAM groups"
  "${AWS[@]}" iam list-groups

  section "IAM roles (summary)"
  "${AWS[@]}" iam list-roles \
    --query 'Roles[].{Name:RoleName,CreateDate:CreateDate,LastUsed:RoleLastUsed.LastUsedDate}' \
    --output table

  section "Roles with AdministratorAccess"
  while read -r role; do
    [[ -z "$role" ]] && continue
    attached="$("${AWS[@]}" iam list-attached-role-policies \
      --role-name "$role" \
      --query 'AttachedPolicies[?PolicyArn==`arn:aws:iam::aws:policy/AdministratorAccess`].PolicyArn' \
      --output text 2>/dev/null || true)"
    if [[ -n "$attached" ]]; then
      echo "$role"
    fi
  done < <("${AWS[@]}" iam list-roles --query 'Roles[].RoleName' --output text | tr '\t' '\n')

  section "Users with AdministratorAccess"
  while read -r user; do
    [[ -z "$user" ]] && continue
    attached="$("${AWS[@]}" iam list-attached-user-policies \
      --user-name "$user" \
      --query 'AttachedPolicies[?PolicyArn==`arn:aws:iam::aws:policy/AdministratorAccess`].PolicyArn' \
      --output text 2>/dev/null || true)"
    if [[ -n "$attached" ]]; then
      echo "$user"
    fi
  done < <("${AWS[@]}" iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n')

  section "Groups with AdministratorAccess"
  while read -r group; do
    [[ -z "$group" ]] && continue
    attached="$("${AWS[@]}" iam list-attached-group-policies \
      --group-name "$group" \
      --query 'AttachedPolicies[?PolicyArn==`arn:aws:iam::aws:policy/AdministratorAccess`].PolicyArn' \
      --output text 2>/dev/null || true)"
    if [[ -n "$attached" ]]; then
      echo "$group"
    fi
  done < <("${AWS[@]}" iam list-groups --query 'Groups[].GroupName' --output text | tr '\t' '\n')

  section "Active IAM access keys"
  while read -r user; do
    [[ -z "$user" ]] && continue
    keys="$("${AWS[@]}" iam list-access-keys \
      --user-name "$user" \
      --query "AccessKeyMetadata[?Status=='Active']" \
      --output json 2>/dev/null || true)"
    if [[ "$keys" != "[]" && -n "$keys" ]]; then
      echo "$user"
      echo "$keys"
    fi
  done < <("${AWS[@]}" iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n')

  section "Account password policy"
  if ! "${AWS[@]}" iam get-account-password-policy; then
    echo "Password policy: not configured."
  fi

  section "Credential report (first five lines)"
  "${AWS[@]}" iam generate-credential-report >/dev/null 2>&1 || true
  report="$("${AWS[@]}" iam get-credential-report --query Content --output text 2>/dev/null || true)"
  if [[ -n "$report" ]]; then
    if ! echo "$report" | base64 --decode 2>/dev/null | head -5; then
      if ! echo "$report" | base64 -d 2>/dev/null | head -5; then
        echo "$report" | base64 -D 2>/dev/null | head -5 || echo "Credential report decode failed."
      fi
    fi
  else
    echo "Credential report unavailable."
  fi

  section "S3 account public access block"
  account_id="$("${AWS[@]}" sts get-caller-identity --query Account --output text)"
  if ! "${AWS[@]}" s3control get-public-access-block --account-id "$account_id"; then
    echo "S3 account public access block: not configured."
  fi

  section "GuardDuty"
  if ! "${AWS[@]}" guardduty list-detectors; then
    echo "GuardDuty: not enabled or not accessible."
  fi

  section "IAM Access Analyzer"
  if ! "${AWS[@]}" accessanalyzer list-analyzers; then
    echo "Access Analyzer: not enabled or not accessible."
  fi

  section "CloudTrail"
  if ! "${AWS[@]}" cloudtrail describe-trails; then
    echo "CloudTrail: not configured or not accessible."
  fi

  section "Audit complete"
  echo "Finished at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

if [[ -n "$OUTPUT_DIR" ]]; then
  mkdir -p "$OUTPUT_DIR"
  log_file="${OUTPUT_DIR}/audit-${timestamp}.log"
  if command -v tee >/dev/null 2>&1; then
    run_audit 2>&1 | tee "$log_file"
  else
    run_audit >"$log_file" 2>&1
    cat "$log_file"
  fi
else
  run_audit
fi
