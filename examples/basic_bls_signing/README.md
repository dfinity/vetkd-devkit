# Basic BLS Signing

> [!IMPORTANT]  
> These support libraries are under active development and are subject to change. Access to the repositories have been opened to allow for early feedback. Please check back regularly for updates.

The **Basic BLS signing** example demonstrates how to use **[VetKeys](https://internetcomputer.org/docs/building-apps/network-features/encryption/vetkeys)** to implement secure BLS signing on the **Internet Computer (IC)**, where every authenticated user can ask the canister (IC smart contract) to produce signatures for their **Internet Identity Principal** as identifier of the signer. This canister ensures that users can only produce signature for their own principal and not for someone else's principal. Furthermore, the vetKeys in this dapp can only be produce upon a user request, as specified in the canister code, meaning that the canister can not produce signatures for arbitrary users or messages.

Since for confirming that the canister can only produce signatures in the intended way users need to inspect the code installed in the canister, it is crucial that canisters using VetKeys have their code public.

![UI Screenshot](ui_screenshot.png)

## Features

- **Signer Authorization**: Only authorized users can produce signatures and only for their own identity.
- **Frontend Signature Verification**: Any user can publish any signature from their principal in the canister storage and the frontend automatically checks the signature validity.

## Setup

### Prerequisites

- [Internet Computer software development kit](https://internetcomputer.org/docs/building-apps/getting-started/install)
- [npm](https://www.npmjs.com/package/npm)

### Install Dependencies

```bash
npm install
```

### Deploy the Canisters

Run the local deployment script, which starts the local development environment (`dfx`) if necessary, builds both backend and frontend (asset) canisters, and installs them locally.
```bash
bash deploy_locally.sh
```

## Example Components

### Backend

The backend consists of a canister that:
* Produces signatures upon a user request.
* Allows users to retrieve the root public key that can be used to check any user's signature for this canister.
* Allows users to store signatures (real or fake) in a log datastructure.

### Frontend

The frontend is a vanilla typescript application providing a simple interface for signing, showing the signatures stored in the canister, and publishing a signature.

To run the frontend in development mode with hot reloading (after running `deploy_locally.sh`):

```bash
npm run dev
```

## Additional Resources

- **[What are VetKeys](https://internetcomputer.org/docs/building-apps/network-features/encryption/vetkeys)** - For more information about VetKeys and VetKD.
