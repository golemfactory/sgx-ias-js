import Axios from "axios";
import { Base64 } from "js-base64";
import { sgx } from ".";
import { AttestationRequest, AttestationResponse } from "./src/attest";

const URL_DEV: string = "https://api.trustedservices.intel.com/sgx/dev";
const URL_PROD: string = "https://api.trustedservices.intel.com/sgx";
const SIGRL_PATH: string = "/attestation/v4/sigrl";
const REPORT_PATH: string = "/attestation/v4/report";

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
