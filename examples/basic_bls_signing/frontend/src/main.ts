// Required to run `npm run dev`.
if (!window.global) {
  window.global = window;
}

import "./style.css";
import { createActor } from "../../src/declarations/basic_bls_signing";
import { Principal } from "@dfinity/principal";
import { AuthClient } from "@dfinity/auth-client";
import type { ActorSubclass } from "@dfinity/agent";
import { _SERVICE } from "../../src/declarations/basic_bls_signing/basic_bls_signing.did";
import { DerivedPublicKey, augmentedHashToG1 } from "@dfinity/vetkeys";
import { bls12_381 } from "@noble/curves/bls12-381";

let myPrincipal: Principal | undefined = undefined;
let authClient: AuthClient | undefined;
let basicBlsSigningCanister: ActorSubclass<_SERVICE> | undefined;
let rootPublicKey: DerivedPublicKey | undefined;

function getBasicBlsSigningCanister(): ActorSubclass<_SERVICE> {
  if (basicBlsSigningCanister) return basicBlsSigningCanister;
  if (!process.env.CANISTER_ID_BASIC_BLS_SIGNING) {
    throw Error("CANISTER_ID_BASIC_BLS_SIGNING is not set");
  }
  if (!authClient) {
    throw Error("Auth client is not initialized");
  }
  const host =
    process.env.DFX_NETWORK === "ic"
      ? `https://${process.env.CANISTER_ID_BASIC_BLS_SIGNING}.ic0.app`
      : "http://localhost:8000";

  basicBlsSigningCanister = createActor(
    process.env.CANISTER_ID_BASIC_BLS_SIGNING,
    process.env.DFX_NETWORK === "ic"
      ? undefined
      : {
          agentOptions: {
            identity: authClient.getIdentity(),
            host,
          },
        },
  );

  return basicBlsSigningCanister;
}

export function login(client: AuthClient) {
  client.login({
    maxTimeToLive: BigInt(1800) * BigInt(1_000_000_000),
    identityProvider:
      process.env.DFX_NETWORK === "ic"
        ? "https://identity.ic0.app/#authorize"
        : `http://${process.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:8000/#authorize`,
    onSuccess: async () => {
      myPrincipal = client.getIdentity().getPrincipal();
      updateUI(true);
    },
    onError: (error) => {
      alert("Authentication failed: " + error);
    },
  });
}

export function logout() {
  authClient?.logout();
  myPrincipal = undefined;
  updateUI(false);
  document.getElementById("signaturesList")!.style.display = "none";
}

async function initAuth() {
  authClient = await AuthClient.create();
  const isAuthenticated = await authClient.isAuthenticated();

  if (isAuthenticated) {
    myPrincipal = authClient.getIdentity().getPrincipal();
    updateUI(true);
  } else {
    updateUI(false);
  }
}

function updateUI(isAuthenticated: boolean) {
  const loginButton = document.getElementById("loginButton")!;
  const principalDisplay = document.getElementById("principalDisplay")!;
  const logoutButton = document.getElementById("logoutButton")!;
  const signingActions = document.getElementById("signingActions")!;
  const customSignatureForm = document.getElementById("customSignatureForm")!;
  const signaturesList = document.getElementById("signaturesList")!;

  loginButton.style.display = isAuthenticated ? "none" : "block";
  principalDisplay.style.display = isAuthenticated ? "block" : "none";
  logoutButton.style.display = isAuthenticated ? "block" : "none";
  signingActions.style.display = isAuthenticated ? "block" : "none";
  customSignatureForm.style.display = "none";
  signaturesList.style.display = "none";

  if (isAuthenticated && myPrincipal) {
    principalDisplay.textContent = `Principal: ${myPrincipal.toString()}`;
  }
}

async function handleLogin() {
  if (!authClient) {
    alert("Auth client not initialized");
    return;
  }
  login(authClient);
}

document.querySelector<HTMLDivElement>("#app")!.innerHTML = `
  <div>
    <h1>Basic BLS Signing using VetKeys</h1>
    <div class="principal-container">
      <div id="principalDisplay" class="principal-display"></div>
      <button id="logoutButton" style="display: none;">Logout</button>
    </div>
    <div class="login-container">
      <button id="loginButton">Login</button>
    </div>
    <div id="signingActions" class="buttons" style="display: none;">
      <button id="signMessageButton">Sign Message</button>
      <button id="customSignatureButton">Add Custom Signature</button>
      <button id="listSignaturesButton">List Signatures</button>
    </div>
    <div id="customSignatureForm" style="display: none;">
      <h3>Add Custom Signature</h3>
      <form id="submitSignatureForm">
        <div>
          <label for="message">Message</label>
          <input type="text" id="message" required>
        </div>
        <div>
          <label for="signature">Signature (hex)</label>
          <input type="text" id="signature" required>
        </div>
        <button type="submit">Submit</button>
      </form>
    </div>
    <div id="signaturesList" style="display: none;">
      <h3>Published Signatures</h3>
      <div id="signatures"></div>
    </div>
  </div>
`;

// Add event listeners
document.getElementById("loginButton")!.addEventListener("click", handleLogin);
document.getElementById("logoutButton")!.addEventListener("click", logout);
document
  .getElementById("signMessageButton")!
  .addEventListener("click", async () => {
    const message = prompt("Enter message to sign:");
    if (message) {
      try {
        const signature =
          await getBasicBlsSigningCanister().sign_message(message);
        const publish = confirm(
          "Signature generated successfully. Would you like to publish it?",
        );
        if (publish) {
          await getBasicBlsSigningCanister().publish_my_signature_no_verification(
            message,
            signature,
          );
          alert("Signature published successfully!");
        }
      } catch (error) {
        alert(`Error: ${error}`);
      }
    }
  });

document
  .getElementById("customSignatureButton")!
  .addEventListener("click", () => {
    document.getElementById("customSignatureForm")!.style.display = "block";
    document.getElementById("signaturesList")!.style.display = "none";
  });

document
  .getElementById("listSignaturesButton")!
  .addEventListener("click", listSignatures);

document
  .getElementById("submitSignatureForm")!
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = (document.getElementById("message") as HTMLInputElement)
      .value;
    const signatureHex = (
      document.getElementById("signature") as HTMLInputElement
    ).value;

    try {
      const signature = new Uint8Array(
        signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
      );
      await getBasicBlsSigningCanister().publish_my_signature_no_verification(
        message,
        signature,
      );
      alert("Signature published successfully!");
      document.getElementById("customSignatureForm")!.style.display = "none";
    } catch (error) {
      alert(`Error: ${error}`);
    }
  });

async function listSignatures() {
  if (!rootPublicKey) {
    const rootPublicKeyRaw =
      await getBasicBlsSigningCanister().get_root_public_key();
    rootPublicKey = DerivedPublicKey.deserialize(
      Uint8Array.from(rootPublicKeyRaw),
    );
  }

  const signatures =
    await getBasicBlsSigningCanister().get_published_signatures();
  const signaturesDiv = document.getElementById("signatures")!;
  signaturesDiv.innerHTML = "";

  if (signatures.length === 0) {
    signaturesDiv.innerHTML = `
        <div class="no-signatures">
          <p>No signatures have been published yet.</p>
        </div>
      `;
  } else {
    signatures
      .slice()
      .reverse()
      .forEach((signatureData) => {
        const isMe =
          myPrincipal && signatureData.signer.compareTo(myPrincipal) === "eq";
        const signatureHex = Array.from(signatureData.signature)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");

        // Convert nanoseconds to milliseconds and create a Date object
        const timestamp = new Date(Number(signatureData.timestamp) / 1_000_000);
        const formattedDate = timestamp.toLocaleString();

        const signatureElement = document.createElement("div");
        signatureElement.className = "signature";
        const isValid = verifySignature(
          signatureData.message,
          Uint8Array.from(signatureData.signature),
          signatureData.signer,
        );
        signatureElement.innerHTML = `
          <h5>Signed message: ${signatureData.message}</h5>
          <p class="principal ${isMe ? "principal-me" : ""}">${signatureData.signer.toString()}</p>
          <p class="signature-hex">${signatureHex}</p>
          <p class="verification-status ${isValid ? "valid" : "invalid"}">Verification: ${isValid ? "Valid" : "Invalid"}</p>
          <p class="timestamp">Added: ${formattedDate}</p>
        `;
        signaturesDiv.appendChild(signatureElement);
      });
  }

  document.getElementById("signaturesList")!.style.display = "block";
  document.getElementById("customSignatureForm")!.style.display = "none";
}

function verifySignature(
  message: string,
  signature: Uint8Array,
  signer: Principal,
): boolean {
  if (!rootPublicKey) {
    throw new Error("Root public key not found");
  }
  const domainSepBytes = new TextEncoder().encode("basic_bls_signing_dapp");
  const domainSetLength = domainSepBytes.length;
  const context = new Uint8Array([
    domainSetLength,
    ...domainSepBytes,
    ...signer.toUint8Array(),
  ]);

  try {
    const signatureG1 = bls12_381.G1.ProjectivePoint.fromHex(signature);
    const negG2 = bls12_381.G2.ProjectivePoint.BASE.negate();
    const dpk = rootPublicKey.deriveKey(context);
    const messageBytes = new TextEncoder().encode(message);
    const msg = augmentedHashToG1(dpk, messageBytes);
    const check = bls12_381.pairingBatch([
      { g1: signatureG1, g2: negG2 },
      { g1: msg, g2: dpk.getPoint() },
    ]);

    const gtOne = bls12_381.fields.Fp12.ONE;

    return bls12_381.fields.Fp12.eql(check, gtOne);
  } catch {
    return false;
  }
}

// Initialize auth
initAuth();
