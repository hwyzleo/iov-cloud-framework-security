# CR-005: DataKeyDistributionTemplate & SESSION Dual-Mode - Tasks

> **Requirements SSOT**: Notion Page `38f0ec7a4b928093b8f0e33bf2f6b338` (FW-SEC-REQ-CR-005)
> **Design SSOT**: Notion Page `38f0ec7a4b928083bf7aead343e9be4d` (FW-SEC-DSN-CR-005)
> **Design CR**: Notion Page `f63760265f3a4fc4b4f7e2af12564b6b`

## Conventions
- [ ] = TODO, [x] = Done, ~~strikethrough~~ = Cancelled
- Task granularity: 0.5-2 days per task

## Task List

- [x] **T-CR005-1** Add `CryptoMode` enum and field to `BizType` · US-012, US-014 · Deps: none
- [x] **T-CR005-2** Add `WrappedDataKey`, `DeviceRecipient`, `SessionKeyMaterial`, `KdfParams` models · US-013, US-014 · Deps: none
- [x] **T-CR005-3** Add `mode` / `salt` fields to `EnvelopeHeader` and `CipherPayload` · US-005, US-014 · Deps: none
- [x] **T-CR005-4** Update `EnvelopeCodec` for `mode` discriminator + SESSION header (backward compatible: ver=1 no mode, ver=2 with mode) · US-005, US-014 · Deps: T-CR005-3
- [x] **T-CR005-5** Add `wrapActiveDataKeyForDevice` / `deriveSessionRoot` to `KmsClient` SPI · US-013, US-014 · Deps: T-CR005-2
- [x] **T-CR005-6** Add `SessionKdf` (HKDF-SHA256) utility · US-014 · Deps: none
- [x] **T-CR005-7** Update `DefaultCryptoTemplate` for ENVELOPE/SESSION dual-mode dispatch · US-001, US-014 · Deps: T-CR005-1, T-CR005-4, T-CR005-5, T-CR005-6
- [x] **T-CR005-8** Add `DataKeyDistributionTemplate` interface + `DefaultDataKeyDistributionTemplate` impl · US-013 · Deps: T-CR005-2, T-CR005-5
- [x] **T-CR005-9** Add `crypto.keyprov.enabled` config to `CryptoProperties` · US-013 · Deps: none
- [x] **T-CR005-10** Add conditional bean wiring in `CryptoAutoConfiguration` · US-013 · Deps: T-CR005-8, T-CR005-9
- [x] **T-CR005-11** Implement new `KmsClient` methods in `FeignKmsClient`, `DefaultKmsClient`, `KmsFeignClient` · US-013, US-014 · Deps: T-CR005-5
- [x] **T-CR005-12** Add keyprov / session metrics to `CryptoMetrics` · US-008 · Deps: none
- [x] **T-CR005-13** Write unit tests for all new code · US-013, US-014 · Deps: T-CR005-1 through T-CR005-12
  - [x] BizType CryptoMode tests
  - [x] EnvelopeCodec mode backward-compat + SESSION encoding tests
  - [x] SessionKdf HKDF-SHA256 tests
  - [x] DefaultCryptoTemplate SESSION mode encrypt/decrypt round-trip + legacy backward compat tests
  - [x] DefaultDataKeyDistributionTemplate fail-closed + validation tests
  - [x] FeignKmsClient new method tests (covered by compilation + integration)

## Change Requests
### CR-005 (2026-07-08): DataKeyDistributionTemplate + SESSION dual-mode + CryptoMode
- See tasks above
