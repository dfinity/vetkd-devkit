import "./style.css";
import { basic_ibe as basicIbeCanister } from "../../src/declarations/basic_ibe";
import { Principal } from "@dfinity/principal";
import {
  TransportSecretKey,
  DerivedPublicKey,
  EncryptedVetKey,
  VetKey,
  IdentityBasedEncryptionCiphertext,
} from "ic_vetkeys";
import { Message, Inbox } from "../../src/declarations/basic_ibe/basic_ibe.did";
import { AuthClient } from "@dfinity/auth-client";

// Store the IBE key in memory
let ibePrivateKey: VetKey | undefined = undefined;
let ibePublicKey: DerivedPublicKey | undefined = undefined;
let myPrincipal: Principal | undefined = undefined;
let authClient: AuthClient | undefined;

// Get the root IBE public key
async function getRootIbePublicKey(): Promise<DerivedPublicKey> {
  if (ibePublicKey) return ibePublicKey;
  return DerivedPublicKey.deserialize(
    new Uint8Array(await basicIbeCanister.get_root_ibe_public_key())
  );
}

// Get the user's encrypted IBE key
async function getIbeKey(): Promise<VetKey> {
  if (ibePrivateKey) return ibePrivateKey;

  if (!myPrincipal) {
    throw Error("My principal is not set");
  } else {
    const transportSecretKey = TransportSecretKey.random();
    const encryptedKey = Uint8Array.from(
      await basicIbeCanister.get_my_encrypted_ibe_key(
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
    ); // Placeholder for encrypted message

    const result = await basicIbeCanister.send_message({
      encrypted_message: encryptedMessage.serialize(),
      receiver: Principal.fromText(receiver),
    });

    if ("Err" in result) {
      console.error("Error sending message: " + result.Err);
    } else {
      console.info("Message sent successfully!");
    }
  } catch (error) {
    console.error("Error: " + error);
  }
}

async function showMessages() {
    const inbox = await basicIbeCanister.get_my_messages();
    await displayMessages(inbox);
}

async function deleteSelectedMessages() {
  try {
    const inbox = await basicIbeCanister.remove_my_messages();
    await displayMessages(inbox);
  } catch (error) {
    alert("Error deleting messages: " + error);
  }
}

function createMessageElement(
  sender: Principal,
  timestamp: bigint,
  index: number,
  plaintextString: string
): HTMLDivElement {
  const messageElement = document.createElement("div");
  messageElement.className = "message";

  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.id = `message-${index}`;

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

  messageInfo.appendChild(senderInfo);
  messageInfo.appendChild(timestampInfo);
  messageContent.appendChild(messageText);
  messageContent.appendChild(messageInfo);

  messageElement.appendChild(checkbox);
  messageElement.appendChild(messageContent);

  return messageElement;
}

async function decryptMessage(encryptedMessage: Uint8Array): Promise<string> {
  const ibeKey = await getIbeKey();
  const ciphertext = IdentityBasedEncryptionCiphertext.deserialize(encryptedMessage);
  const plaintext = ciphertext.decrypt(ibeKey);
  return new TextDecoder().decode(plaintext);
}

async function displayMessages(inbox: Inbox) {
  const messagesDiv = document.getElementById("messages")!;
  messagesDiv.innerHTML = "";

  for (const [index, message] of inbox.messages.entries()) {
    const plaintextString = await decryptMessage(new Uint8Array(message.encrypted_message));
    
    const messageElement = createMessageElement(
      message.sender,
      message.timestamp,
      index,
      plaintextString
    );
    messagesDiv.appendChild(messageElement);
  }

  const deleteButton = document.getElementById("deleteMessages")!;
  deleteButton.style.display = inbox.messages.length > 0 ? "block" : "none";
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

  loginButton.style.display = isAuthenticated ? "none" : "block";
  messageButtons.style.display = isAuthenticated ? "flex" : "none";
  principalDisplay.style.display = isAuthenticated ? "block" : "none";

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
    <h1>IBE Message System</h1>
    <div id="principalDisplay" class="principal-display"></div>
    <button id="loginButton">Login</button>
    <div id="messageButtons" class="buttons" style="display: none;">
      <button id="sendMessage">Send Message</button>
      <button id="showMessages">Show My Messages</button>
    </div>
    <div id="messages"></div>
    <button id="deleteMessages" style="display: none;">Delete Selected Messages</button>
  </div>
`;

// Add event listeners
document.getElementById("loginButton")!.addEventListener("click", handleLogin);
document.getElementById("sendMessage")!.addEventListener("click", sendMessage);
document
  .getElementById("showMessages")!
  .addEventListener("click", showMessages);
document
  .getElementById("deleteMessages")!
  .addEventListener("click", deleteSelectedMessages);

// Initialize auth
initAuth();
