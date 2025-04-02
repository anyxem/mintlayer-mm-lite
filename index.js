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
    const password = await getPassword(program.opts());
    const key = loadKey(password, path.join(__dirname, `${DEFAULT_WALLET_NAME}${KEY_FILE_EXT}`));
    console.log('Showing balance for key:', key);
    // Your balance display logic goes here
    rl.close();
  });

program
  .command('create-order')
  .description('Create an order')
  .action(async () => {
    const password = await getPassword(program.opts());
    const key = loadKey(password, path.join(__dirname, `${DEFAULT_WALLET_NAME}${KEY_FILE_EXT}`));
    console.log('Creating order with key:', key);
    // Your order creation logic goes here
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
