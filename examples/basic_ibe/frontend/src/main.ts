// Required to run `npm run dev`.
if (!window.global) {
  window.global = window;
}

import "./style.css";
import { createActor } from "../../src/declarations/basic_ibe";
import { Principal } from "@dfinity/principal";
import {
  TransportSecretKey,
  DerivedPublicKey,
  EncryptedVetKey,
  VetKey,
  IdentityBasedEncryptionCiphertext,
} from "@dfinity/vetkeys";
import {
  Inbox,
  _SERVICE,
} from "../../src/declarations/basic_ibe/basic_ibe.did";
import { AuthClient } from "@dfinity/auth-client";
import type { ActorSubclass } from "@dfinity/agent";

// Store the IBE key in memory
let ibePrivateKey: VetKey | undefined = undefined;
let ibePublicKey: DerivedPublicKey | undefined = undefined;
let myPrincipal: Principal | undefined = undefined;
let authClient: AuthClient | undefined;
let basicIbeCanister: ActorSubclass<_SERVICE> | undefined;

function getBasicIbeCanister(): ActorSubclass<_SERVICE> {
  if (basicIbeCanister) return basicIbeCanister;
  if (!process.env.CANISTER_ID_BASIC_IBE) {
    throw Error("CANISTER_ID_BASIC_IBE is not set");
  }
  if (!authClient) {
    throw Error("Auth client is not initialized");
  }
  const host =
    process.env.DFX_NETWORK === "ic"
      ? `https://${process.env.CANISTER_ID_BASIC_IBE}.ic0.app`
      : "http://localhost:8000";

  basicIbeCanister = createActor(
    process.env.CANISTER_ID_BASIC_IBE,
    process.env.DFX_NETWORK === "ic"
      ? undefined
      : {
          agentOptions: {
            identity: authClient.getIdentity(),
            host,
          },
        }
  );

  return basicIbeCanister;
}

// Get the root IBE public key
async function getRootIbePublicKey(): Promise<DerivedPublicKey> {
  if (ibePublicKey) return ibePublicKey;
  ibePublicKey = DerivedPublicKey.deserialize(
    new Uint8Array(await getBasicIbeCanister().get_root_ibe_public_key())
  );
  return ibePublicKey;
}

// Get the user's encrypted IBE key
async function getMyIbePrivateKey(): Promise<VetKey> {
  if (ibePrivateKey) return ibePrivateKey;

  if (!myPrincipal) {
    throw Error("My principal is not set");
  } else {
    const transportSecretKey = TransportSecretKey.random();
    const encryptedKey = Uint8Array.from(
      await getBasicIbeCanister().get_my_encrypted_ibe_key(
        transportSecretKey.publicKeyBytes()
      )
    );
    ibePrivateKey = new EncryptedVetKey(encryptedKey).decryptAndVerify(
      transportSecretKey,
      await getRootIbePublicKey(),
      new Uint8Array(myPrincipal.toUint8Array())
    );
    return ibePrivateKey;
  }
}

// Send a message
async function sendMessage() {
  const message = prompt("Enter your message:");
  if (!message) throw Error("Message is required");

  const receiver = prompt("Enter receiver principal:");
  if (!receiver) throw Error("Receiver is required");

  const receiverPrincipal = Principal.fromText(receiver);

  try {
    const publicKey = await getRootIbePublicKey();
    const seed = new Uint8Array(32);
    window.crypto.getRandomValues(seed);

    const encryptedMessage = IdentityBasedEncryptionCiphertext.encrypt(
      publicKey,
      receiverPrincipal.toUint8Array(),
      new TextEncoder().encode(message),
      seed
    );

    const result = await getBasicIbeCanister().send_message({
      encrypted_message: encryptedMessage.serialize(),
      receiver: receiverPrincipal,
    });

    if ("Err" in result) {
      alert("Error sending message: " + result.Err);
    } else {
      alert("Message sent successfully!");
    }
  } catch (error) {
    alert("Error sending message: " + error);
  }
}

async function showMessages() {
  const inbox = await getBasicIbeCanister().get_my_messages();
  await displayMessages(inbox);
}

async function decryptMessage(encryptedMessage: Uint8Array): Promise<string> {
  const ibeKey = await getMyIbePrivateKey();
  const ciphertext =
    IdentityBasedEncryptionCiphertext.deserialize(encryptedMessage);
  const plaintext = ciphertext.decrypt(ibeKey);
  return new TextDecoder().decode(plaintext);
}

function createMessageElement(
  sender: Principal,
  timestamp: bigint,
  plaintextString: string,
  index: number
): HTMLDivElement {
  const messageElement = document.createElement("div");
  messageElement.className = "message";

  const messageContent = document.createElement("div");
  messageContent.className = "message-content";

  const messageText = document.createElement("div");
  messageText.className = "message-text";
  messageText.textContent = plaintextString;

  const messageInfo = document.createElement("div");
  messageInfo.className = "message-info";

  const senderInfo = document.createElement("div");
  senderInfo.className = "sender";
  senderInfo.textContent = `From: ${sender.toString()}`;

  const timestampInfo = document.createElement("div");
  timestampInfo.className = "timestamp";
  const date = new Date(Number(timestamp) / 1_000_000);
  timestampInfo.textContent = `Sent: ${date.toLocaleString()}`;

  const messageActions = document.createElement("div");
  messageActions.className = "message-actions";

  const deleteButton = document.createElement("button");
  deleteButton.className = "delete-button";
  deleteButton.textContent = "Delete";
  deleteButton.dataset.index = index.toString();

  messageActions.appendChild(deleteButton);
  messageInfo.appendChild(senderInfo);
  messageInfo.appendChild(timestampInfo);
  messageContent.appendChild(messageText);
  messageContent.appendChild(messageInfo);
  messageContent.appendChild(messageActions);
  messageElement.appendChild(messageContent);

  return messageElement;
}

async function displayMessages(inbox: Inbox) {
  const messagesDiv = document.getElementById("messages")!;
  messagesDiv.innerHTML = "";

  if (inbox.messages.length === 0) {
    const noMessagesDiv = document.createElement("div");
    noMessagesDiv.className = "no-messages";
    noMessagesDiv.textContent = "No messages in the inbox.";
    messagesDiv.appendChild(noMessagesDiv);
    return;
  }

  // Iterate through messages in reverse order
  for (let i = inbox.messages.length - 1; i >= 0; i--) {
    const message = inbox.messages[i];
    const plaintextString = await decryptMessage(
      new Uint8Array(message.encrypted_message)
    );

    const messageElement = createMessageElement(
      message.sender,
      message.timestamp,
      plaintextString,
      i
    );
    messagesDiv.appendChild(messageElement);
  }

  // Add event listeners to delete buttons
  const deleteButtons = document.querySelectorAll(".delete-button");
  deleteButtons.forEach(button => {
    button.addEventListener("click", async (e) => {
      const target = e.target as HTMLButtonElement;
      const index = parseInt(target.dataset.index!);
      
      // Disable all delete buttons
      deleteButtons.forEach(btn => (btn as HTMLButtonElement).disabled = true);
      
      try {
        const result = await getBasicIbeCanister().remove_my_message_by_index(BigInt(index));
        if ("Err" in result) {
          alert("Error deleting message: " + result.Err);
        } else {
          // Remove the message element from the DOM
          const messageElement = target.closest('.message');
          if (messageElement) {
            messageElement.remove();
            
            // If this was the last message, show the "no messages" message
            const messagesDiv = document.getElementById("messages")!;
            if (messagesDiv.children.length === 0) {
              const noMessagesDiv = document.createElement("div");
              noMessagesDiv.className = "no-messages";
              noMessagesDiv.textContent = "No messages in the inbox.";
              messagesDiv.appendChild(noMessagesDiv);
            }
          }
        }
      } catch (error) {
        alert("Error deleting message: " + error);
      } finally {
        // Re-enable all delete buttons
        deleteButtons.forEach(btn => (btn as HTMLButtonElement).disabled = false);
      }
    });
  });
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
  const messagesDiv = document.getElementById("messages")!;
  messagesDiv.innerHTML = "";
  ibePrivateKey = undefined;
  myPrincipal = undefined;
  basicIbeCanister = undefined;
  updateUI(false);
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
  const messageButtons = document.getElementById("messageButtons")!;
  const principalDisplay = document.getElementById("principalDisplay")!;
  const logoutButton = document.getElementById("logoutButton")!;

  loginButton.style.display = isAuthenticated ? "none" : "block";
  messageButtons.style.display = isAuthenticated ? "flex" : "none";
  principalDisplay.style.display = isAuthenticated ? "block" : "none";
  logoutButton.style.display = isAuthenticated ? "block" : "none";

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
    <h1>Basic IBE Message System with VetKeys</h1>
    <div class="principal-container">
      <div id="principalDisplay" class="principal-display"></div>
      <button id="logoutButton" style="display: none;">Logout</button>
    </div>
    <div class="login-container">
      <button id="loginButton">Login</button>
    </div>
    <div id="messageButtons" class="buttons" style="display: none;">
      <button id="sendMessage">Send Message</button>
      <button id="showMessages">Show My Messages</button>
    </div>
    <div id="messages"></div>
  </div>
`;

// Add event listeners
document.getElementById("loginButton")!.addEventListener("click", handleLogin);
document.getElementById("logoutButton")!.addEventListener("click", logout);
document.getElementById("sendMessage")!.addEventListener("click", sendMessage);
document
  .getElementById("showMessages")!
  .addEventListener("click", showMessages);

// Initialize auth
initAuth();
