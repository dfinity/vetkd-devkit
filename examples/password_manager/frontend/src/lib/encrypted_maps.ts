import "./init.ts";
import { HttpAgent, type HttpAgentOptions } from "@dfinity/agent";
import { DefaultEncryptedMapsClient } from "../../../../../sdk/ic_vetkd_sdk_encrypted_maps_example/src/index";
import { EncryptedMaps } from "ic_vetkd_sdk_encrypted_maps/src";

export async function createEncryptedMaps(
    agentOptions?: HttpAgentOptions,
): Promise<EncryptedMaps> {
    const CANISTER_ID_ENCRYPTED_MAPS_EXAMPLE =
        process.env.CANISTER_ID_ENCRYPTED_MAPS_EXAMPLE;
    const host =
        process.env.DFX_NETWORK === "ic"
            ? `https://${CANISTER_ID_ENCRYPTED_MAPS_EXAMPLE}.ic0.app`
            : "http://localhost:8000";
    const hostOptions = { host };

    if (!agentOptions) {
        agentOptions = hostOptions;
    } else {
        agentOptions.host = hostOptions.host;
    }

    const agent = await HttpAgent.create({ ...agentOptions });
    // Fetch root key for certificate validation during development
    if (process.env.NODE_ENV !== "production") {
        console.log(`Dev environment - fetching root key...`);

        agent.fetchRootKey().catch((err) => {
            console.warn(
                "Unable to fetch root key. Check to ensure that your local replica is running",
            );
            console.error(err);
        });
    }

    // Creates an actor with using the candid interface and the HttpAgent
    return new EncryptedMaps(
        new DefaultEncryptedMapsClient(
            agent,
            CANISTER_ID_ENCRYPTED_MAPS_EXAMPLE,
        ),
    );
}
