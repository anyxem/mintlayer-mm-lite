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

// Path to the encrypted key file next to the script (default name)
const DEFAULT_WALLET_NAME = 'encrypted_wallet_key';
const KEY_FILE_EXT = '.bin';

const DEFAULT_NETWORK = "1" // testnet

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

// Load the key at startup
function loadKey(password, filePath) {
  if (fs.existsSync(filePath)) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return decryptKey(data, password);
  } else {
    console.log('Key not found. Create a wallet using the "create-wallet" command.');
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

// Get unique file path for the wallet
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
  .option('-p, --password <password>', 'Password to decrypt the key');

program
  .command('create-wallet')
  .description('Create a new wallet with a seed phrase')
  .action(async () => {
    console.log('Creating a new wallet...');

    // Get password
    const password = await getPassword(program.opts());

    // Prompt for seed phrase (mandatory)
    const seedPhrase = await promptUser('Enter seed phrase (mandatory): ');
    if (!seedPhrase.trim()) {
      console.log('Seed phrase cannot be empty. Aborting...');
      rl.close();
      return;
    }

    // Prompt for wallet name (optional)
    const walletName = await promptUser('Enter wallet name (press Enter for default): ');
    const filePath = getUniqueFilePath(walletName.trim());

    // Encrypt and save the seed phrase
    const encrypted = encryptKey(seedPhrase, password);
    fs.writeFileSync(filePath, JSON.stringify(encrypted));
    console.log('Wallet created, key saved to', filePath);

    rl.close();
  });

program
  .command('show-addresses')
  .description('Show wallet addresses')
  .action(async () => {
    const password = await getPassword(program.opts());
    const seed = loadKey(password, path.join(__dirname, `${DEFAULT_WALLET_NAME}${KEY_FILE_EXT}`));
    const accountPrivKey = make_default_account_privkey(seed, DEFAULT_NETWORK);

    let keyIndex = 0;
    const batchSize = 10;

    async function showNextBatch() {
      const addresses = [];
      for (let i = 0; i < batchSize && keyIndex < 100; i++, keyIndex++) { // Arbitrary limit of 100, adjust as needed
        const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
        const pk = public_key_from_private_key(receivingKey);
        const receivingAddress = pubkey_to_pubkeyhash_address(pk, DEFAULT_NETWORK);
        addresses.push({ Index: keyIndex, Address: receivingAddress });
      }

      console.table(addresses);

      if (keyIndex < 100) { // Continue if there are more to show
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
    const seed = loadKey(password, path.join(__dirname, `${DEFAULT_WALLET_NAME}${KEY_FILE_EXT}`));
    const accountPrivKey = make_default_account_privkey(seed, DEFAULT_NETWORK);

    const addresses = [];
    const totalAddresses = 50; // Fetch 100 addresses at once

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
      const pk = public_key_from_private_key(receivingKey);
      const receivingAddress = pubkey_to_pubkeyhash_address(pk, DEFAULT_NETWORK);
      addresses.push(receivingAddress);
    }

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const changeKey = make_change_address(accountPrivKey, keyIndex);
      const rk = public_key_from_private_key(changeKey);
      const changeAddress = pubkey_to_pubkeyhash_address(rk, DEFAULT_NETWORK);
      addresses.push(changeAddress);
    }

    // Fetch balances from the API
    const response = await fetch(WALLET_API + '/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ addresses, network: parseInt(DEFAULT_NETWORK) })
    });

    if (!response.ok) {
      console.error('Failed to fetch balances:', response.statusText);
      rl.close();
      return;
    }

    const data = await response.json();

    const tokenTable = data.tokens.map((token, idx) => ({
      // Index: idx,
      Symbol: token.symbol,
      Balance: token.balance,
      // Value: token.value,
      Type: token.type,
      // Ticker: token.symbol || 'N/A',
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
    const seed = loadKey(password, path.join(__dirname, `${DEFAULT_WALLET_NAME}${KEY_FILE_EXT}`));
    const accountPrivKey = make_default_account_privkey(seed, DEFAULT_NETWORK);

    const addresses = [];
    const addressesPrivateKeys = {};
    const totalAddresses = 50; // Fetch 100 addresses at once

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const receivingKey = make_receiving_address(accountPrivKey, keyIndex);
      const pk = public_key_from_private_key(receivingKey);
      const receivingAddress = pubkey_to_pubkeyhash_address(pk, DEFAULT_NETWORK);
      addressesPrivateKeys[receivingAddress] = receivingKey;
      addresses.push(receivingAddress);
    }

    for (let keyIndex = 0; keyIndex < totalAddresses; keyIndex++) {
      const changeKey = make_change_address(accountPrivKey, keyIndex);
      const rk = public_key_from_private_key(changeKey);
      const changeAddress = pubkey_to_pubkeyhash_address(rk, DEFAULT_NETWORK);
      addressesPrivateKeys[changeAddress] = changeKey;
      addresses.push(changeAddress);
    }

    // Fetch balances from the API
    const response = await fetch(WALLET_API + '/account', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ addresses, network: parseInt(DEFAULT_NETWORK) })
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
    const ratio = sellAmount / buyAmount;

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
    const network = parseInt(DEFAULT_NETWORK);

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
      // encode_create_order_output(
      //   ask_amount, ask_token_id, give_amount, give_token_id, conclude_address, network
      // )
    ];

    // step 2. Determine inputs

    console.log('tokens', tokens);
    console.log('give_token_id', give_token_id);

    const sendToken = tokens.find((t) => t.token_id === give_token_id);

    console.log('sendToken', sendToken);

    console.log('amountToken', amountToken);

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

    console.log("transactionJSONrepresentation:", JSON.stringify(transactionJSONrepresentation, null, 2));

    const transactionBINrepresentation = getTransactionBINrepresentation(transactionJSONrepresentation);

    console.log("transactionBINrepresentation:", transactionBINrepresentation);

    const transactionHex = getTransactionHEX({transactionBINrepresentation, transactionJSONrepresentation, addressesPrivateKeys});

    console.log(`transactionHex:`);
    console.log(transactionHex);
    // Prompt to broadcast
    const broadcast = await promptUser('Do you want to broadcast this to the network using API server? (Y/n): ');
    if (broadcast.toLowerCase() === 'y') {
      // Placeholder for API broadcast (adjust endpoint and payload as needed)
      const broadcastResponse = await fetch(WALLET_API + '/transaction', {
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
  .command('cancel-order')
  .description('Cancel an order')
  .action(async () => {
    const password = await getPassword(program.opts());
    const key = loadKey(password, path.join(__dirname, `${DEFAULT_WALLET_NAME}${KEY_FILE_EXT}`));
    console.log('Canceling order with key:', key);
    // Your order cancellation logic goes here
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

const NETWORKS = {
  mainnet: 0,
  testnet: 1,
  regtest: 2,
  signet: 3,
}

const getOutputs = ({
                      amount,
                      address,
                      networkType,
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

  const networkIndex = networkType
  if (type === 'Transfer') {
    const amountInstace = Amount.from_atoms(amount);
    if (tokenId) {
      return encode_output_token_transfer(
        amountInstace,
        address,
        tokenId,
        networkIndex,
      )
    } else {
      return encode_output_transfer(amountInstace, address, networkIndex)
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
        networkIndex,
      )
    }
    if (lock.type === 'ForBlockCount' && !chainTip) {
      const lockEncoded = encode_lock_for_block_count(BigInt(lock.content))
      return encode_output_lock_then_transfer(
        amountInstance,
        address,
        lockEncoded,
        networkIndex,
      )
    }
    if (lock.type === 'ForBlockCount' && chainTip) {
      const stakingMaturity = staking_pool_spend_maturity_block_count(chainTip.toString(), networkIndex);
      const lockEncoded = encode_lock_for_block_count(stakingMaturity);
      return encode_output_lock_then_transfer(
        amountInstance,
        address,
        lockEncoded,
        networkIndex,
      )
    }
  }
  if(type === 'CreateDelegationId') {
    return encode_output_create_delegation(poolId, address, networkIndex)
  }
  if(type === 'DelegateStaking') {
    const amountInstace = Amount.from_atoms(amount);
    return encode_output_delegate_staking(amountInstace, delegation_id, networkIndex)
  }
  // if (type === 'spendFromDelegation') {
  //   const stakingMaturity = getStakingMaturity(chainTip, networkType)
  //   const encodedLockForBlock = encode_lock_for_block_count(stakingMaturity)
  //   return encode_output_lock_then_transfer(
  //     amountInstace,
  //     address,
  //     encodedLockForBlock,
  //     networkIndex,
  //   )
  // }
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


function getTransactionBINrepresentation(transactionJSONrepresentation) {
  const network = parseInt(DEFAULT_NETWORK);
  // Binarisation
  // calculate fee and prepare as much transaction as possible
  const inputs = transactionJSONrepresentation.inputs;
  console.log('inputs', inputs);
  const transactionStrings = inputs.map((input) => ({
    transaction: input.outpoint.source_id,
    index: input.outpoint.index,
  }));
  console.log('transactionStrings', transactionStrings);
  const transactionBytes = transactionStrings.map((transaction) => ({
    bytes: Buffer.from(transaction.transaction, 'hex'),
    index: transaction.index,
  }));
  console.log('transactionBytes', transactionBytes);
  const outpointedSourceIds = transactionBytes.map((transaction) => ({
    source_id: encode_outpoint_source_id(transaction.bytes, SourceId.Transaction),
    index: transaction.index,
  }));
  console.log('outpointedSourceIds', outpointedSourceIds);
  const inputsIds = outpointedSourceIds.map((source) => (encode_input_for_utxo(source.source_id, source.index)));
  console.log('inputsIds', inputsIds);
  const inputsArray = inputsIds;

  const outputsArrayItems = transactionJSONrepresentation.outputs.map((output) => {
    if (output.type === 'Transfer') {
      return getOutputs({
        amount: BigInt(output.value.amount.atoms).toString(),
        address: output.destination,
        networkType: network,
        ...(output?.value?.token_id ? { tokenId: output.value.token_id } : {}),
      })
    }
    if (output.type === 'CreateOrder') {
      try{
        console.log('output.conclude_destination', output.conclude_destination);
        encode_create_order_output(
          Amount.from_atoms(output.ask_balance.atoms.toString()), //ask_amount
          output.ask_currency.token_id || null,  // ask_token_id
          Amount.from_atoms(output.give_balance.atoms.toString()), //give_amount
          output.give_currency.token_id || null, //give_token_id
          output.conclude_destination, // conclude_address
          NETWORKS['testnet'], // network
        )
      } catch (e){
        console.log(e);
      }
      return encode_create_order_output(
        Amount.from_atoms(output.ask_balance.atoms.toString()), //ask_amount
        output.ask_currency.token_id || null,  // ask_token_id
        Amount.from_atoms(output.give_balance.atoms.toString()), //give_amount
        output.give_currency.token_id || null, //give_token_id
        output.conclude_destination, // conclude_address
        NETWORKS['testnet'], // network
      );
    }
  })
  console.log('outputsArrayItems', outputsArrayItems);
  const outputsArray = outputsArrayItems;

  const inputAddresses = transactionJSONrepresentation.inputs.map((input) => input.utxo.destination);
  console.log('inputAddresses', inputAddresses);

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

function getTransactionHEX ({transactionBINrepresentation, transactionJSONrepresentation, addressesPrivateKeys}) {
  const inputsArray = transactionBINrepresentation.inputs;
  const outputsArray = transactionBINrepresentation.outputs;
  const transaction = encode_transaction(mergeUint8Arrays(inputsArray), mergeUint8Arrays(outputsArray), BigInt(0));
  const network = NETWORKS['testnet'];

  const optUtxos_ = transactionJSONrepresentation.inputs.map((input) => {
    if (input.utxo.type === 'Transfer') {
      return getOutputs({
        amount: BigInt(input.utxo.value.amount.atoms).toString(),
        address: input.utxo.destination,
        networkType: network,
        ...(input?.utxo?.value?.token_id ? { tokenId: input.utxo.value.token_id } : {}),
      })
    }
    if (input.utxo.type === 'LockThenTransfer') {
      return getOutputs({
        amount: BigInt(input.utxo.value.amount.atoms).toString(),
        address: input.utxo.destination,
        networkType: network,
        type: 'LockThenTransfer',
        lock: input.utxo.lock,
        ...(input?.utxo?.value?.token_id ? { tokenId: input.utxo.value.token_id } : {}),
      })
    }
  });


  const optUtxos = []
  for (let i = 0; i < optUtxos_.length; i++) {
    optUtxos.push(1)
    optUtxos.push(...optUtxos_[i])
  }

  const encodedWitnesses = transactionJSONrepresentation.inputs.map((input, index) => {
    const address = input.utxo.destination;
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
