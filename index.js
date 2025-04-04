const { program } = require('commander');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const {
  public_key_from_private_key,
  make_default_account_privkey,
  make_receiving_address,
  pubkey_to_pubkeyhash_address,
  make_change_address,
  encode_create_order_output,
  encode_outpoint_source_id,
  encode_output_transfer,
  Amount,
  encode_input_for_utxo,
  encode_signed_transaction,
  encode_transaction,
  encode_witness,
  estimate_transaction_size,
  SignatureHashType,
  encode_output_token_transfer,
  SourceId
} = require('./mintlayer-wasm-lib/release/wasm_wrappers');
const {encode_input_for_conclude_order} = require("./mintlayer-wasm-lib/release");

// Default values
const DEFAULT_WALLET_NAME = 'encrypted_wallet_key';
const KEY_FILE_EXT = '.bin';
const DEFAULT_NETWORK = 'testnet'; // Default to testnet

// Network mapping
const NETWORKS = {
  mainnet: 0,
  testnet: 1,
  regtest: 2,
  signet: 3,
};

// Create readline interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Function to encrypt the key
function encryptKey(key, password) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(password.padEnd(32, ' ')), iv);
  let encrypted = cipher.update(key, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encrypted };
}

// Function to decrypt the key
function decryptKey(encryptedData, password) {
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(password.padEnd(32, ' ')),
    Buffer.from(encryptedData.iv, 'hex')
  );
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Load the key from a specified file
function loadKey(password, filePath) {
  if (fs.existsSync(filePath)) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return decryptKey(data, password);
  } else {
    console.log(`Key file "${filePath}" not found. Create it using the "create-wallet" command.`);
    process.exit(1);
  }
}

// Prompt user for input with a question
function promptUser(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

// Get password (from argument or prompt)
async function getPassword(commandOpts) {
  if (commandOpts.password) {
    return commandOpts.password;
  }
  return promptUser('Enter password: ');
}

// Get network (from argument or prompt)
async function getNetwork(commandOpts) {
  if (commandOpts.network) {
    const network = commandOpts.network.toLowerCase();
    if (NETWORKS[network] !== undefined) {
      return network;
    } else {
      console.log(`Invalid network "${network}". Use "testnet" or "mainnet". Defaulting to "${DEFAULT_NETWORK}".`);
    }
  }
  const networkInput = await promptUser(`Enter network (testnet/mainnet, default: ${DEFAULT_NETWORK}): `);
  const network = networkInput.trim().toLowerCase() || DEFAULT_NETWORK;
  if (NETWORKS[network] === undefined) {
    console.log(`Invalid network "${network}". Using default "${DEFAULT_NETWORK}".`);
    return DEFAULT_NETWORK;
  }
  return network;
}

// Get wallet file path (from argument or prompt)
async function getWalletFilePath(commandOpts, defaultName = DEFAULT_WALLET_NAME) {
  if (commandOpts.file) {
    return path.join(__dirname, `${commandOpts.file}${KEY_FILE_EXT}`);
  }
  const fileInput = await promptUser(`Enter wallet file name (default: ${defaultName}): `);
  const fileName = fileInput.trim() || defaultName;
  return path.join(__dirname, `${fileName}${KEY_FILE_EXT}`);
}

// Get unique file path for wallet creation
function getUniqueFilePath(walletName) {
  let baseName = walletName || DEFAULT_WALLET_NAME;
  let filePath = path.join(__dirname, `${baseName}${KEY_FILE_EXT}`);
  let counter = 1;

  while (fs.existsSync(filePath)) {
    filePath = path.join(__dirname, `${baseName}_${counter}${KEY_FILE_EXT}`);
    counter++;
  }
  return filePath;
}

// Configure commands using commander
program
  .version('1.0.0')
  .option('-p, --password <password>', 'Password to decrypt the key')
  .option('-n, --network <network>', 'Network to use (testnet or mainnet)')
  .option('-f, --file <filename>', 'Wallet file name (without .bin extension)');

program
  .command('create-wallet')
  .description('Create a new wallet with a seed phrase')
  .action(async () => {
    console.log('Creating a new wallet...');

    // Get password
    const password = await getPassword(program.opts());
    const network = await getNetwork(program.opts());
    const seedPhrase = await promptUser('Enter seed phrase (mandatory): ');
    if (!seedPhrase.trim()) {
      console.log('Seed phrase cannot be empty. Aborting...');
      rl.close();
      return;
    }
    const walletName = await promptUser(`Enter wallet file name (default: ${DEFAULT_WALLET_NAME}): `);
    const filePath = getUniqueFilePath(walletName.trim());

    const encrypted = encryptKey(seedPhrase, password);
    fs.writeFileSync(filePath, JSON.stringify(encrypted));
    console.log(`Wallet created for ${network}, key saved to`, filePath);

    rl.close();
  });

program
  .command('show-addresses')
  .description('Show wallet addresses')
  .action(async () => {
    const password = await getPassword(program.opts());
    const network = await getNetwork(program.opts());
    const filePath = await getWalletFilePath(program.opts());
    const seed = loadKey(password, filePath);
    const accountPrivKey = make_default_account_privkey(seed, NETWORKS[network]);

    let keyIndex = 0;
    const batchSize = 10;

    async function showNextBatch() {
      const addresses = [];
      for (let i = 0; i < batchSize && keyIndex < 100; i++, keyIndex++) {
        const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
        const pk = public_key_from_private_key(receivingKey);
        const receivingAddress = pubkey_to_pubkeyhash_address(pk, NETWORKS[network]);
        addresses.push({ Index: keyIndex, Address: receivingAddress });
      }

      console.table(addresses);

      if (keyIndex < 100) {
        const response = await promptUser('Press "c" to show more addresses or any key to exit: ');
        if (response.toLowerCase() === 'c') {
          await showNextBatch();
        } else {
          console.log('Exiting address display...');
          rl.close();
        }
      } else {
        console.log('No more addresses to show.');
        rl.close();
      }
    }

    await showNextBatch();
  });

program
  .command('show-balance')
  .description('Show wallet balance')
  .action(async () => {
    const WALLET_API = 'https://api.mintini.app';
    const password = await getPassword(program.opts());
    const network = await getNetwork(program.opts());
    const filePath = await getWalletFilePath(program.opts());
    const seed = loadKey(password, filePath);
    const accountPrivKey = make_default_account_privkey(seed, NETWORKS[network]);

    const addresses = [];
    const totalAddresses = 50;

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
      const pk = public_key_from_private_key(receivingKey);
      const receivingAddress = pubkey_to_pubkeyhash_address(pk, NETWORKS[network]);
      addresses.push(receivingAddress);
    }

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const changeKey = make_change_address(accountPrivKey, keyIndex);
      const rk = public_key_from_private_key(changeKey);
      const changeAddress = pubkey_to_pubkeyhash_address(rk, NETWORKS[network]);
      addresses.push(changeAddress);
    }

    const response = await fetch(WALLET_API + '/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ addresses, network: NETWORKS[network] })
    });

    if (!response.ok) {
      console.error('Failed to fetch balances:', response.statusText);
      rl.close();
      return;
    }

    const data = await response.json();
    const tokenTable = data.tokens.map((token, idx) => ({
      Symbol: token.symbol,
      Balance: token.balance,
      Type: token.type,
      'Token ID': token.token_id || token.token_details?.token_id || 'N/A'
    }));

    console.table(tokenTable);
    rl.close();
  });

program
  .command('create-order')
  .description('Create an order')
  .action(async () => {
    const WALLET_API = 'https://api.mintini.app';
    const password = await getPassword(program.opts());
    const network = await getNetwork(program.opts());
    const filePath = await getWalletFilePath(program.opts());
    const seed = loadKey(password, filePath);
    const accountPrivKey = make_default_account_privkey(seed, NETWORKS[network]);

    const addresses = [];
    const addressesPrivateKeys = {};
    const totalAddresses = 50;

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
      const pk = public_key_from_private_key(receivingKey);
      const receivingAddress = pubkey_to_pubkeyhash_address(pk, NETWORKS[network]);
      addressesPrivateKeys[receivingAddress] = receivingKey;
      addresses.push(receivingAddress);
    }

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const changeKey = make_change_address(accountPrivKey, keyIndex);
      const rk = public_key_from_private_key(changeKey);
      const changeAddress = pubkey_to_pubkeyhash_address(rk, NETWORKS[network]);
      addressesPrivateKeys[changeAddress] = changeKey;
      addresses.push(changeAddress);
    }

    // Fetch balances from the API
    const response = await fetch(WALLET_API + '/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ addresses, network: NETWORKS[network] })
    });

    if (!response.ok) {
      console.error('Failed to fetch balances:', response.statusText);
      rl.close();
      return;
    }

    const data = await response.json();
    const tokens = data.tokens;

    const utxos = data.utxos;

    // Display current balances
    console.log('Current balances:');
    const balanceTable = tokens.map((token, idx) => ({
      Index: idx,
      Symbol: token.symbol,
      'Token ID': token.token_id || token.token_details?.token_id || 'N/A',
      Amount: token.balance
    }));
    console.table(balanceTable);

    // Prompt for token to sell
    const sellChoice = await promptUser('Enter the Index or Symbol of the token to sell: ');
    const sellToken = tokens.find((t, i) => i === parseInt(sellChoice) || t.symbol === sellChoice);
    if (!sellToken) {
      console.log('Invalid selection. Aborting...');
      rl.close();
      return;
    }

    // Prompt for sell amount
    const sellAmount = parseFloat(await promptUser(`Enter amount to sell (${sellToken.symbol}, max ${sellToken.balance}): `));
    if (isNaN(sellAmount) || sellAmount <= 0 || sellAmount > sellToken.balance) {
      console.log('Invalid amount. Aborting...');
      rl.close();
      return;
    }

    // Prompt for token to buy (default ML)
    const buyInput = await promptUser('Enter token to buy (press Enter for ML, or specify token_id): ');
    const buySymbol = buyInput.trim() ? buyInput : 'ML';
    const buyTokenId = buyInput.trim() && buyInput !== 'ML' ? buyInput : null;

    // Prompt for buy amount
    const buyAmount = parseFloat(await promptUser(`Enter amount to buy (${buySymbol}): `));
    if (isNaN(buyAmount) || buyAmount <= 0) {
      console.log('Invalid amount. Aborting...');
      rl.close();
      return;
    }

    // Calculate ratio
    const ratio = buyAmount / sellAmount;

    // Show order details and confirm
    console.log('\nOrder Details:');
    console.log(`Pair: ${sellToken.symbol}/${buySymbol}`);
    console.log(`Sell: ${sellAmount} ${sellToken.symbol}`);
    console.log(`Buy: ${buyAmount} ${buySymbol}`);
    console.log(`Ratio: 1 ${sellToken.symbol} = ${ratio.toFixed(6)} ${buySymbol}`);
    const confirm = await promptUser('Confirm order? (Y/n): ');
    if (confirm.toLowerCase() !== 'y') {
      console.log('Order cancelled.');
      rl.close();
      return;
    }

    // Example order text
    const orderText = `Order: Sell ${sellAmount} ${sellToken.symbol} for ${buyAmount} ${buySymbol} at ratio ${ratio.toFixed(6)}`;
    console.log(orderText);

    // Build transaction
    const give_amount = sellAmount;
    const give_token_id = sellToken.token_id || sellToken.token_details?.token_id || 'Coin';
    const ask_amount = buyAmount;
    const ask_token_id = buyTokenId || 'Coin';
    const conclude_address = addresses[0]; // Use the first address for simplicity

    const amountCoin = 0n;
    const amountToken = BigInt(give_amount * Math.pow(10, sellToken.token_details.number_of_decimals));

    // step 1. Determine initial outputs
    const outputObj = [
      {
        "type": "CreateOrder",
        "ask_balance": {
          "atoms": ask_amount * Math.pow(10, 11),
          "decimal": ask_amount
        },
        "ask_currency": {
          "type": "Coin"
        },
        "conclude_destination": conclude_address,
        "give_balance": {
          "atoms": give_amount * Math.pow(10, sellToken.token_details.number_of_decimals),
          "decimal": give_amount
        },
        "give_currency": {
          "token_id": give_token_id,
          "type": "Token"
        },
        "initially_asked": {
          "atoms": ask_amount * Math.pow(10, sellToken.token_details.number_of_decimals),
          "decimal": ask_amount
        },
        "initially_given": {
          "atoms": give_amount * Math.pow(10, sellToken.token_details.number_of_decimals),
          "decimal": give_amount
        },
      }
    ];

    // step 2. Determine inputs

    const sendToken = tokens.find((t) => t.token_id === give_token_id);

    const fee = BigInt(0.5 * Math.pow(10, 11));

    const pickCoin = amountCoin + fee; // TODO more precise pick
    const inputObjCoin = selectUTXOs(utxos, pickCoin, 'Transfer', null);
    const inputObjToken = sendToken?.token_id ? selectUTXOs(utxos, amountToken, 'Transfer', sendToken?.token_id) : [];

    // step 3. Calculate total input value
    const totalInputValueCoin = inputObjCoin.reduce((acc, item) => acc + BigInt(item.utxo.value.amount.atoms), 0n);
    const totalInputValueToken = inputObjToken.reduce((acc, item) => acc + BigInt(item.utxo.value.amount.atoms), 0n);

    const changeAmountCoin = totalInputValueCoin - amountCoin - fee;
    const changeAmountToken = totalInputValueToken - amountToken;

    // step 4. Add change if necessary
    if (changeAmountCoin > 0) {
      outputObj.push({
        type: 'Transfer',
        value: {
          type: 'Coin',
          amount: {
            atoms: changeAmountCoin.toString(),
            decimal: (changeAmountCoin.toString() / 1e11).toString(),
          },
        },
        destination: addresses[0], // change address
      });
    }

    if (changeAmountToken > 0) {
      const decimals = sendToken.token_details.number_of_decimals;

      outputObj.push({
        type: 'Transfer',
        value: {
          type: 'TokenV1',
          token_id: sendToken.token_id,
          amount: {
            atoms: changeAmountToken.toString(),
            decimal: (changeAmountToken.toString() / Math.pow(10, decimals)).toString(),
          },
        },
        destination: addresses[0], // change address
      });
    }

    const transactionJSONrepresentation = {
      inputs: [
        ...inputObjCoin,
        ...inputObjToken,
      ],
      outputs: outputObj,
    }

    console.log('transactionJSONrepresentation', transactionJSONrepresentation);

    const transactionBINrepresentation = getTransactionBINrepresentation(transactionJSONrepresentation, NETWORKS[network]);

    const transactionHex = getTransactionHEX({transactionBINrepresentation, transactionJSONrepresentation, addressesPrivateKeys}, NETWORKS[network]);

    console.log(`transactionHex:`);
    console.log(transactionHex);
    // Prompt to broadcast
    const broadcast = await promptUser('Do you want to broadcast this to the network using API server? (Y/n): ');
    if (broadcast.toLowerCase() === 'y') {
      // Placeholder for API broadcast (adjust endpoint and payload as needed)
      const broadcastResponse = await fetch( 'https://api-server-lovelace.mintlayer.org/api/v2/transaction', {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain'
        },
        body: transactionHex
      });

      if (broadcastResponse.ok) {
        console.log('Order broadcasted successfully.');
      } else {
        console.error('Failed to broadcast order:', broadcastResponse.statusText);
      }
    } else {
      console.log('Order not broadcasted.');
    }

    rl.close();
  });

program
  .command('conclude-order')
  .description('Conclude an order')
  .action(async () => {
    const WALLET_API = 'https://api.mintini.app';
    const ORDER_API = 'https://api-server-lovelace.mintlayer.org/api/v2';
    const password = await getPassword(program.opts());
    const network = await getNetwork(program.opts());
    const filePath = await getWalletFilePath(program.opts());
    const seed = loadKey(password, filePath);
    const accountPrivKey = make_default_account_privkey(seed, NETWORKS[network]);

    const addresses = [];
    const addressesPrivateKeys = {};
    const totalAddresses = 50;

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
      const pk = public_key_from_private_key(receivingKey);
      const receivingAddress = pubkey_to_pubkeyhash_address(pk, NETWORKS[network]);
      addressesPrivateKeys[receivingAddress] = receivingKey;
      addresses.push(receivingAddress);
    }

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const changeKey = make_change_address(accountPrivKey, keyIndex);
      const rk = public_key_from_private_key(changeKey);
      const changeAddress = pubkey_to_pubkeyhash_address(rk, NETWORKS[network]);
      addressesPrivateKeys[changeAddress] = changeKey;
      addresses.push(changeAddress);
    }

    // Fetch balances from the API
    const response = await fetch(WALLET_API + '/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ addresses, network: NETWORKS[network] })
    });

    if (!response.ok) {
      console.error('Failed to fetch balances:', response.statusText);
      rl.close();
      return;
    }

    const data = await response.json();

    const tokens = data.tokens;

    // Fetch orders from the API
    const responseOrder = await fetch(ORDER_API + '/order', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      },
    });

    if (!responseOrder.ok) {
      console.error('Failed to fetch orders:', responseOrder.statusText);
      rl.close();
      return;
    }

    const dataOrders = await responseOrder.json();

    // Display current balances
    console.log('Your Orders:');
    const orderTable = dataOrders
      .filter(({conclude_destination}) => addresses.includes(conclude_destination))
      .filter(({ask_balance, give_balance}) => ask_balance.atoms > 0 && give_balance.atoms > 0)
      .map((order, idx) => ({
        Index: idx,
        OrderId: order.order_id,
        give: (order.give_balance.decimal < 1 ? "!!" : "") + order.give_balance.decimal + ' ' + (order.give_currency.token_id ? tokens.find(({token_id}) => token_id === order.give_currency.token_id ).symbol : order.give_currency.type),
        ask: order.initially_asked.decimal - order.ask_balance.decimal + ' ' + (order.ask_currency.token_id ? order.ask_currency.token_id : order.ask_currency.type),
      }));
    console.table(orderTable);

    const utxos = data.utxos;

    // Prompt for order_id
    const orderId = await promptUser('Enter the order ID to conclude: ');
    if (!orderId.trim()) {
      console.log('Order ID cannot be empty. Aborting...');
      rl.close();
      return;
    }

    // Fetch order details
    const orderResponse = await fetch(`${ORDER_API}/order/${orderId}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!orderResponse.ok) {
      console.error('Failed to fetch order details:', orderResponse.statusText);
      rl.close();
      return;
    }

    const orderData = await orderResponse.json();
    // Display order details
    console.log('\nOrder Details:');
    console.log(`Order ID: ${orderData.order_id}`);
    console.log(`Sell: ${orderData.give_balance.decimal} ${orderData.give_currency.token_id ? orderData.give_currency.token_id : orderData.give_currency.type}`);
    console.log(`Buy: ${orderData.ask_balance.decimal} ${orderData.ask_currency.type === 'Coin' ? 'ML' : orderData.ask_currency.token_id || 'Unknown'}`);
    console.log(`Conclude Destination: ${orderData.conclude_destination}`);

    // Confirm action
    const confirm = await promptUser(`Are you sure you want to conclude order ${orderId}? (Y/n): `);
    if (confirm.toLowerCase() !== 'y') {
      console.log('Action cancelled.');
      rl.close();
      return;
    }

    const inputObj = [{
      type: "ConcludeOrder",
      destination: orderData.conclude_destination,
      order_id: orderData.order_id,
      nonce: orderData.nonce,
    }];

    const outputObj = [];

    // output Give
    outputObj.push({
      type: 'Transfer',
      value: {
        type: orderData.give_currency.type === 'Token' ? 'TokenV1' : 'Coin',
        ...(orderData.give_currency.type === 'Token' ? {token_id: orderData.give_currency.token_id} : {}),
        amount: {
          atoms: orderData.give_balance.atoms,
          decimal: orderData.give_balance.decimal,
        },
      },
      destination: orderData.conclude_destination,
    });

    // output Ask
    outputObj.push({
      type: 'Transfer',
      value: {
        type: orderData.ask_currency.type === 'Token' ? 'TokenV1' : 'Coin',
        ...(orderData.ask_currency.type === 'Token' ? {token_id: orderData.ask_currency.token_id} : {}),
        amount: {
          atoms: (orderData.initially_asked.atoms - orderData.ask_balance.atoms).toString(),
          decimal: (orderData.initially_asked.decimal - orderData.ask_balance.decimal).toString(),
        },
      },
      destination: orderData.conclude_destination,
    });


    const amountCoin = 0n;
    const fee = BigInt(1 * Math.pow(10, 11)); // TODO

    const pickCoin = amountCoin + fee; // TODO more precise pick
    const inputObjCoin = selectUTXOs(utxos, pickCoin, 'Transfer', null);

    // step 3. Calculate total input value
    const totalInputValueCoin = inputObjCoin.reduce((acc, item) => acc + BigInt(item.utxo.value.amount.atoms), 0n);

    inputObj.push(...inputObjCoin);

    const changeAmountCoin = totalInputValueCoin - amountCoin - fee;

    // step 4. Add change if necessary
    if (changeAmountCoin > 0) {
      outputObj.push({
        type: 'Transfer',
        value: {
          type: 'Coin',
          amount: {
            atoms: changeAmountCoin.toString(),
            decimal: (changeAmountCoin.toString() / 1e11).toString(),
          },
        },
        destination: addresses[0], // change address
      });
    }


    const transactionJSONrepresentation = {
      inputs: inputObj,
      outputs: outputObj,
    }

    console.log("transactionJSONrepresentation:", JSON.stringify(transactionJSONrepresentation, null, 2));

    const transactionBINrepresentation = getTransactionBINrepresentation(transactionJSONrepresentation, NETWORKS[network]);

    const transactionHex = getTransactionHEX({transactionBINrepresentation, transactionJSONrepresentation, addressesPrivateKeys}, NETWORKS[network]);

    console.log('transactionHex');
    console.log(transactionHex);

    const confirm_broadcast = await promptUser(`Broadcast transaction? (Y/n): `);
    if (confirm_broadcast.toLowerCase() !== 'y') {
      console.log('Action cancelled.');
      rl.close();
      return;
    }

    // Send request to conclude the order
    const concludeResponse = await fetch(`${ORDER_API}/transaction`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain'
      },
      body: transactionHex
    });

    if (concludeResponse.ok) {
      console.log(`Order ${orderId} concluded successfully.`);
    } else {
      console.error('Failed to conclude order:', concludeResponse.statusText);
    }

    rl.close();
  });

// Parse command-line arguments
program.parseAsync(process.argv).catch((err) => {
  console.error('Error:', err.message);
  rl.close();
});

// Show help if no command is provided
if (process.argv.length === 2) {
  program.outputHelp();
  rl.close();
}


// helpers

function mergeUint8Arrays(arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);

  const result = new Uint8Array(totalLength);

  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

const getOutputs = ({
                      amount,
                      address,
                      network,
                      type = 'Transfer',
                      lock,
                      chainTip,
                      tokenId,
                      poolId,
                      delegation_id,
                    }) => {
  if (type === 'LockThenTransfer' && !lock) {
    throw new Error('LockThenTransfer requires a lock')
  }

  if (type === 'Transfer') {
    const amountInstace = Amount.from_atoms(amount);
    if (tokenId) {
      return encode_output_token_transfer(
        amountInstace,
        address,
        tokenId,
        network,
      )
    } else {
      return encode_output_transfer(amountInstace, address, network)
    }
  }
  if (type === 'LockThenTransfer') {
    const amountInstance = Amount.from_atoms(amount);
    if (lock.type === 'UntilTime') {
      const lockEncoded = encode_lock_until_time(BigInt(lock.content.timestamp))
      return encode_output_lock_then_transfer(
        amountInstance,
        address,
        lockEncoded,
        network,
      )
    }
    if (lock.type === 'ForBlockCount' && !chainTip) {
      const lockEncoded = encode_lock_for_block_count(BigInt(lock.content))
      return encode_output_lock_then_transfer(
        amountInstance,
        address,
        lockEncoded,
        network,
      )
    }
    if (lock.type === 'ForBlockCount' && chainTip) {
      const stakingMaturity = staking_pool_spend_maturity_block_count(chainTip.toString(), network);
      const lockEncoded = encode_lock_for_block_count(stakingMaturity);
      return encode_output_lock_then_transfer(
        amountInstance,
        address,
        lockEncoded,
        network,
      )
    }
  }
  if(type === 'CreateDelegationId') {
    return encode_output_create_delegation(poolId, address, network)
  }
  if(type === 'DelegateStaking') {
    const amountInstace = Amount.from_atoms(amount);
    return encode_output_delegate_staking(amountInstace, delegation_id, network)
  }
}

const selectUTXOs = (utxos, amount, outputType, token_id) => {
  if(outputType === 'Transfer') {
    return selectUTXOsForTransfer(utxos, amount, token_id);
  }
}

const selectUTXOsForTransfer = (utxos, amount, token_id) => {
  utxos = utxos.filter((utxo) => {
    if(token_id === null){
      return true;
    }
    return utxo.utxo.value.token_id === token_id;
  });

  let balance = BigInt(0)
  const utxosToSpend = []
  let lastIndex = 0

  // take biggest UTXOs first
  utxos.sort((a, b) => {
    return b.utxo.value.amount.atoms - a.utxo.value.amount.atoms
  })

  for (let i = 0; i < utxos.length; i++) {
    lastIndex = i
    const utxoBalance = BigInt(utxos[i].utxo.value.amount.atoms);
    if (balance < BigInt(amount)) {
      balance += utxoBalance
      utxosToSpend.push(utxos[i])
    } else {
      break
    }
  }

  if (balance === BigInt(amount)) {
    // pick up extra UTXO
    if (utxos[lastIndex + 1]) {
      utxosToSpend.push(utxos[lastIndex + 1])
    }
  }

  return utxosToSpend
}


function getTransactionBINrepresentation(transactionJSONrepresentation, _network) {
  const network = _network;
  // Binarisation
  // calculate fee and prepare as much transaction as possible
  const inputs = transactionJSONrepresentation.inputs;
  const transactionStrings = inputs.filter((input) => input.type !== 'ConcludeOrder').map((input) => ({
    transaction: input.outpoint.source_id,
    index: input.outpoint.index,
  }));
  const transactionBytes = transactionStrings.map((transaction) => ({
    bytes: Buffer.from(transaction.transaction, 'hex'),
    index: transaction.index,
  }));
  const outpointedSourceIds = transactionBytes.map((transaction) => ({
    source_id: encode_outpoint_source_id(transaction.bytes, SourceId.Transaction),
    index: transaction.index,
  }));
  const inputsIds = outpointedSourceIds.map((source) => (encode_input_for_utxo(source.source_id, source.index)));

  const inputCommands = transactionJSONrepresentation.inputs.filter((input) => input.type === 'ConcludeOrder').map((input) => {
    return encode_input_for_conclude_order(
      input.order_id,
      input.nonce.toString(),
      network,
    );
  });

  const inputsArray = [...inputCommands, ...inputsIds];

  const outputsArrayItems = transactionJSONrepresentation.outputs.map((output) => {
    if (output.type === 'Transfer') {
      return getOutputs({
        amount: BigInt(output.value.amount.atoms).toString(),
        address: output.destination,
        network,
        ...(output?.value?.token_id ? { tokenId: output.value.token_id } : {}),
      })
    }
    if (output.type === 'CreateOrder') {
      return encode_create_order_output(
        Amount.from_atoms(output.ask_balance.atoms.toString()), //ask_amount
        output.ask_currency.token_id || null,  // ask_token_id
        Amount.from_atoms(output.give_balance.atoms.toString()), //give_amount
        output.give_currency.token_id || null, //give_token_id
        output.conclude_destination, // conclude_address
        network, // network
      );
    }
  })
  const outputsArray = outputsArrayItems;

  const inputAddresses = transactionJSONrepresentation.inputs.map((input) => input?.utxo?.destination || input?.destination);

  const transactionsize = estimate_transaction_size(
    mergeUint8Arrays(inputsArray),
    inputAddresses,
    mergeUint8Arrays(outputsArray),
    network,
  );

  const feeRate = BigInt(Math.ceil(100000000000 / 1000));

  return {
    inputs: inputsArray,
    outputs: outputsArray,
    transactionsize,
    feeRate,
  }
}

function getTransactionHEX ({transactionBINrepresentation, transactionJSONrepresentation, addressesPrivateKeys}, _network) {
  const network = _network;
  const inputsArray = transactionBINrepresentation.inputs;
  const outputsArray = transactionBINrepresentation.outputs;
  const transaction = encode_transaction(mergeUint8Arrays(inputsArray), mergeUint8Arrays(outputsArray), BigInt(0));

  const optUtxos_ = transactionJSONrepresentation.inputs.map((input) => {
    if (!input.utxo) {
      return 0;
    }
    if (input.utxo.type === 'Transfer') {
      return getOutputs({
        amount: BigInt(input.utxo.value.amount.atoms).toString(),
        address: input.utxo.destination,
        network,
        ...(input?.utxo?.value?.token_id ? { tokenId: input.utxo.value.token_id } : {}),
      })
    }
    if (input.utxo.type === 'LockThenTransfer') {
      return getOutputs({
        amount: BigInt(input.utxo.value.amount.atoms).toString(),
        address: input.utxo.destination,
        network,
        type: 'LockThenTransfer',
        lock: input.utxo.lock,
        ...(input?.utxo?.value?.token_id ? { tokenId: input.utxo.value.token_id } : {}),
      })
    }
  });

  const optUtxos = [];
  for (let i = 0; i < optUtxos_.length; i++) {
    if(transactionJSONrepresentation.inputs[i].type === 'ConcludeOrder') {
      optUtxos.push(0);
      continue;
    } else {
      optUtxos.push(1);
      optUtxos.push(...optUtxos_[i]);
      continue;
    }
  }

  const encodedWitnesses = transactionJSONrepresentation.inputs.map((input, index) => {
    const address = input?.utxo?.destination || input.destination;
    const addressPrivateKey = addressesPrivateKeys[address];

    const witness = encode_witness(
      SignatureHashType.ALL,
      addressPrivateKey,
      address,
      transaction,
      optUtxos,
      index,
      network,
    );
    return witness;
  });

  const encodedSignedTransaction = encode_signed_transaction(transaction, mergeUint8Arrays(encodedWitnesses));
  const txHash = encodedSignedTransaction.reduce((acc, byte) => acc + byte.toString(16).padStart(2, '0'), '')

  return txHash;
}
