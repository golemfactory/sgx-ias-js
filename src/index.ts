import Axios from "axios";
import Base64 from 'js-base64'
import sha512 from "js-sha512";
import jsrsasign from "jsrsasign";
import dayjs from "dayjs";
import duration from "dayjs/plugin/duration";
import utc from "dayjs/plugin/utc";
import * as sgx from "./sgx";
import * as ty from "./types";

dayjs.extend(duration);
dayjs.extend(utc);

const URL_DEV: string = "https://api.trustedservices.intel.com/sgx/dev";
const URL_PROD: string = "https://api.trustedservices.intel.com/sgx";
const SIGRL_PATH: string = "/attestation/v4/sigrl";
const REPORT_PATH: string = "/attestation/v4/report";

const IAS_PUBLIC_KEY_PEM: string = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFi
aGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhk
KWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQj
lytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwn
XnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KA
XJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4
tQIDAQAB
-----END PUBLIC KEY-----
`;

export class IasClient {
    private url!: string;
    private api_key!: string;

    static development(api_key: string, url: string = URL_DEV): IasClient {
        return new IasClient(api_key, url);
    }

    static production(api_key: string, url: string = URL_PROD): IasClient {
        return new IasClient(api_key, url);
    }

    private constructor(api_key: string, url: string) {
        this.url = url;
        this.api_key = api_key;
    }

    async get_sigrl(gid: sgx.SgxEpidGroupId): Promise<Uint8Array> {
        let url = `${this.url}${SIGRL_PATH}/${gid.toString()}`;
        let res = await Axios.get(url, {
            responseType: 'arraybuffer',
            headers: {
                "Ocp-Apim-Subscription-Key": this.api_key,
                "Accept": "application/octet-stream",
            }
        });
        switch (res.status) {
            case 200:
                return res.data;
            default:
                throw new Error(`sigrl request failed (${res.status}): ${res.statusText}`);
        }
    }

    async verify_evidence(quote: Uint8Array, nonce?: string): Promise<AttestationResponse> {
        if (!!nonce && nonce.length > 32) {
            throw new Error(`nonce length ${nonce.length} > 32`);
        }

        let url = `${this.url}${REPORT_PATH}`;
        let data: AttestationRequest = {
            isvEnclaveQuote: Base64.fromUint8Array(quote),
            nonce: nonce,
        };
        let res = await Axios.post(url, {
            data: data,
            headers: {
                "Ocp-Apim-Subscription-Key": this.api_key,
                "Content-type": "application/json",
                "Accept": "text/plain",
            }
        });
        switch (res.status) {
            case 200:
                let ares: AttestationResponse = {
                    report: res.data,
                    signature: Base64.toUint8Array(res.headers["x-iasreport-signature"]),
                };
                return ares;
            default:
                throw new Error(`VAE request failed (${res.status}): ${res.statusText}`);
        }
    }
}

export interface AttestationRequest {
    isvEnclaveQuote: string;
    nonce?: string;
}

export interface AttestationResponse {
    report: string;
    signature: Uint8Array;
}

export interface AttestationResult {
    verdict: AttestationVerdict;
    message?: string;
}

export enum AttestationVerdict {
    Ok,
    InvalidIasReport,
    InvalidMrEnclave,
    InvalidMrSigner,
    InvalidIsvProdId,
    InvalidIsvSvn,
    InvalidQuoteStatus,
    InvalidFlags,
    InvalidReportData,
}

export interface AttestationReport {
    id: string;
    timestamp: string;
    version: ty.u16;
    isvEnclaveQuoteStatus: string;
    isvEnclaveQuoteBody: string;
    revocationReason?: string;
    pseManifestStatus?: string;
    pseManifestHash?: string;
    platformInfoBlob?: string;
    nonce?: string;
    epidPseudonym?: string;
    advisoryURL?: string;
    advisoryIDs?: string[];
}

export class AttestationVerifier {
    constructor(
        private evidence: AttestationResponse,
        private report: AttestationReport,
        private quote: sgx.SgxQuote,
        private hasher: any,
        private result: AttestationResult,
        private check_data: boolean = false,
    ) {}

    static from(response: AttestationResponse): AttestationVerifier {
        let result: AttestationResult = { verdict: AttestationVerdict.Ok };
        let report: AttestationReport;
        let quote: sgx.SgxQuote;

        try {
            report = JSON.parse(response.report);
        } catch(e) {
            report = {
                id: "",
                timestamp: "",
                version: ty.toU16(0),
                isvEnclaveQuoteStatus: "",
                isvEnclaveQuoteBody: "",

            };
            result = {
                verdict: AttestationVerdict.InvalidIasReport,
                message: `Failed to parse IAS report: ${e}`,
            }
        }

        try {
            if (result.verdict != AttestationVerdict.Ok) {
                throw new Error("verdict: failure");
            }
            quote = sgx.SgxQuote.from(Base64.toUint8Array(report.isvEnclaveQuoteBody));
        } catch(e) {
            result = {
                verdict: AttestationVerdict.InvalidIasReport,
                message: `Failed to decode enclave quote: ${e}`,
            }
            quote = sgx.SgxQuote.default();
        }

        return new AttestationVerifier(
            response,
            report,
            quote,
            sha512.create(),
            result,
        );
    }

    private valid(): boolean {
        return this.result.verdict === AttestationVerdict.Ok;
    }

    /// Add custom data to hash. All bytes added using this method are hashed with `SHA512`
    /// and compared with enclave quote's `report_data` field.
    data(data: Uint8Array): AttestationVerifier {
        if (this.valid()) {
            // don't update validity, only check it at the end of verification since
            // this can be chained
            this.hasher.update(data);
            this.check_data = true;
        }
        return this;
    }

    /// Check IAS report's nonce.
    public nonce(nonce: string): AttestationVerifier {
        if (this.valid() && this.report.nonce !== nonce) {
            this.result = {
                verdict: AttestationVerdict.InvalidIasReport,
                message: "Invalid nonce",
            };
        }
        return this;
    }

    /// Check enclave's hash (must match the supplied value).
    public mr_enclave(mr: sgx.SgxMeasurement): AttestationVerifier {
        if (this.valid() && !mr.eq(this.quote.body.report_body.mr_enclave)) {
            this.result = {
                verdict: AttestationVerdict.InvalidMrEnclave,
                message: this.quote.body.report_body.mr_enclave.toString(16),
            };
        }
        return this;
    }

    /// Check enclave's hash (must match any of the supplied values).
    public mr_enclave_list(mrs: sgx.SgxMeasurement[]): AttestationVerifier {
        let this_mr = this.quote.body.report_body.mr_enclave;
        if (this.valid() && !mrs.some((_mr: ty.bytes.Bytes32) => this_mr.eq(_mr))) {
            this.result = {
                verdict: AttestationVerdict.InvalidMrEnclave,
                message: this.quote.body.report_body.mr_enclave.toString(16),
            };
        }
        return this;
    }

    /// Check enclave's hash of signing key (must match the supplied value).
    public mr_signer(mr: sgx.SgxMeasurement): AttestationVerifier {
        if (this.valid() && !mr.eq(this.quote.body.report_body.mr_signer)) {
            this.result = {
                verdict: AttestationVerdict.InvalidMrSigner,
                message: this.quote.body.report_body.mr_signer.toString(16),
            };
        }
        return this;
    }

    /// Check enclave's hash of signing key (must match any of the supplied values).
    public mr_signer_list(mrs: sgx.SgxMeasurement[]): AttestationVerifier {
        let this_mr = this.quote.body.report_body.mr_signer;
        if (this.valid() && !mrs.some((_mr: ty.bytes.Bytes32) => this_mr.eq(_mr))) {
            this.result = {
                verdict: AttestationVerdict.InvalidMrSigner,
                message: this.quote.body.report_body.mr_signer.toString(16),
            };
        }
        return this;
    }

    /// Check enclave's ISV product ID.
    public isv_prod_id(id: ty.u16): AttestationVerifier {
        if (this.valid() && id != this.quote.body.report_body.isv_prod_id) {
            this.result = {
                verdict: AttestationVerdict.InvalidIsvProdId,
                message: this.quote.body.report_body.isv_prod_id.toString(16),
            };
        }
        return this;
    }

    /// Check enclave's security version number.
    public isv_svn(svn: ty.u16): AttestationVerifier {
        if (this.valid() && svn != this.quote.body.report_body.isv_svn) {
            this.result = {
                verdict: AttestationVerdict.InvalidIsvSvn,
                message: this.quote.body.report_body.isv_svn.toString(16),
            };
        }
        return this;
    }

    /// Check that enclave's IAS status is not `GROUP_OUT_OF_DATE` (platform missing security
    /// updates).
    public not_outdated(): AttestationVerifier {
        let quote_status = this.report.isvEnclaveQuoteStatus.toUpperCase();

        if (this.valid() && quote_status == "GROUP_OUT_OF_DATE")
        {
            this.result = {
                verdict: AttestationVerdict.InvalidQuoteStatus,
                message: this.report.isvEnclaveQuoteStatus,
            };
        }
        return this;
    }

    /// Check that enclave is not in debug mode.
    public not_debug(): AttestationVerifier {
        let quote_flags: ty.u64 = this.quote.body.report_body.attributes.flags;

        if (this.valid() && ty.u64Flag(quote_flags, ty.toU64(sgx.SGX_FLAGS_DEBUG))) {
            this.result = {
                verdict: AttestationVerdict.InvalidFlags,
                message: "Enclave has DEBUG flag enabled",
            };
        }
        return this;
    }

    /// Check maximum age of the IAS report (using report's timestamp).
    public max_age(age: duration.Duration): AttestationVerifier {
        if (!this.valid()) {
            return this;
        }

        try {
            let ts = Date.parse(this.report.timestamp);
            let now = dayjs.utc().toDate().getTime();
            if (ts + age.asMilliseconds() < now) {
                this.result = {
                    verdict: AttestationVerdict.InvalidIasReport,
                    message: "IAS response is too old",
                };
            }
        } catch(e) {
            this.result = {
                verdict: AttestationVerdict.InvalidFlags,
                message: "Failed to parse report timestamp",
            };
        }

        return this;
    }

    private verify_sig(): boolean {

        let key = jsrsasign.KEYUTIL.getKey(IAS_PUBLIC_KEY_PEM);
        let sig = new jsrsasign.KJUR.crypto.Signature({alg: "SHA256withRSA"});

        sig.init(key);
        sig.updateString(this.evidence.report);

        if (!sig.verify(ty.toHex(this.evidence.signature))) {
            this.result = {
                verdict: AttestationVerdict.InvalidIasReport,
                message: "Invalid IAS signature",
            };
            return false;
        }

        return true;
    }

    /// Finalize all checks and convert the verifier into attestation result.
    public verify(): AttestationResult {
        if (!this.valid()) {
            return this.result;
        }
        if (!this.verify_sig()) {
            return this.result;
        }

        // GROUP_OUT_OF_DATE is allowed unless filtered out by `not_outdated()`
        let quote_status = this.report.isvEnclaveQuoteStatus.toUpperCase();
        if (quote_status != "OK" && quote_status != "GROUP_OUT_OF_DATE") {
            this.result = {
                verdict: AttestationVerdict.InvalidQuoteStatus,
                message: this.report.isvEnclaveQuoteStatus,
            };
            return this.result;
        }

        let flags = this.quote.body.report_body.attributes.flags;
        if (!ty.u64Flag(flags, sgx.ENCLAVE_FLAGS_NEEDED)) {
            this.result = {
                verdict: AttestationVerdict.InvalidFlags,
                message: "Enclave is not initialized or not 64bit",
            };
            return this.result;
        }

        if (this.check_data) {
            let report_data = this.quote.body.report_body.report_data;
            let hash = new Uint8Array(this.hasher.arrayBuffer());
            if (!report_data.partialEq(hash))
            {
                this.result = {
                    verdict: AttestationVerdict.InvalidReportData,
                    message: this.quote.body.report_body.report_data.toString(16),
                };
                return this.result;
            }
        }

        return this.result;
    }
}
