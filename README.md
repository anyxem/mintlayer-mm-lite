# Token Trading Tool

This is a console-based tool built with Node.js for creating and managing token trading orders. It allows you to input a seed phrase, view derived addresses, check token balances, and create buy/sell orders using an API server.

## Features
- **Initialize with Seed**: Store an encrypted seed phrase with a custom file name.
- **Show Addresses**: Display up to 100 derived addresses in a table.
- **Show Balance**: Fetch and display token balances from the API.
- **Create Order**: Create a sell/buy order with confirmation and optional broadcasting.
- **Conclude Order**: Close an existing order by providing the order ID and getting the remain tokens.

## Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher recommended)
- npm (comes with Node.js)

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/anyxem/mintlayer-mm-lite.git
   ```
2. Navigate to the project directory:
   ```bash
   cd mintlayer-mm-lite
   ```
3. Install dependencies:
   ```bash
   npm install
   ```

## Usage
Run commands using `node ./index.js` followed by the desired command and options.

### Commands

#### Initialize with Seed
Stores an encrypted seed phrase for trading operations.
```
node ./index.js create-wallet [-p <password>]
```
- Prompts for a password (or use `-p` to specify it).
- Prompts for a mandatory seed phrase.
- Prompts for an optional file name (defaults to `encrypted_wallet_key`).
- Saves the encrypted seed to a `.bin` file (e.g., `encrypted_wallet_key.bin`).

#### Show Addresses
Displays up to 100 derived addresses for trading.
```
node ./index.js show-addresses [-p <password>]
```
- Prompts for the password if not provided.
- Shows a table with `Index` and `Address` columns.

#### Show Balance
Fetches and displays current token balances.
```
node ./index.js show-balance [-p <password>]
```
- Prompts for the password if not provided.
- Shows a table with `Symbol`, `Balance`, `Value`, `Type`, `Ticker`, and `Token ID`.

#### Create Order
Creates a token trading order.
```
node ./index.js create-order [-p <password>]
```
- Prompts for the password if not provided.
- Displays current balances.
- Prompts to select a token to sell (by Index or Symbol).
- Prompts for the sell amount.
- Prompts for the token to buy (defaults to `ML`, or enter a `token_id`).
- Prompts for the buy amount.
- Shows order details (pair, amounts, ratio) and asks for confirmation (`Y/n`).
- If confirmed, shows the order text and asks to broadcast to the network (`Y/n`).

### Examples

#### Initialize with Seed
```
node ./index.js create-wallet -p mypass
```
- Enter seed phrase: `my secret seed phrase`
- Enter file name: `mytrade`
- Output: `Seed saved to /path/to/mytrade.bin`

#### Show Addresses
```
node ./index.js show-addresses -p mypass
```
- Displays a table of 100 addresses.

#### Show Balance
```
node ./index.js show-balance -p mypass
```
- Displays a table of token balances.

#### Create an Order
```
node ./index.js create-order -p mypass
```
- Select token to sell: `MLS01`
- Enter sell amount: `100`
- Enter token to buy: (press Enter for `ML`)
- Enter buy amount: `5`
- Confirm: `Y`
- Broadcast: `Y`
- Output: `Order broadcasted successfully.`

## Notes
- The encrypted seed file (e.g., `encrypted_wallet_key.bin`) is stored in the same directory as the tool.
- If a file name already exists, a suffix (e.g., `_1`) is added.
- The tool uses `https://api.mintini.app` for balance and order operations (ensure this API is accessible).
- Address derivation functions (`make_default_account_privkey`, etc.) are placeholders. Replace them with actual implementations for real blockchain use.

## Contributing
Feel free to open issues or submit pull requests on GitHub!

## License
MIT License


