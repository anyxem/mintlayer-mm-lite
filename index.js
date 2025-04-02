const { program } = require('commander');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Path to the encrypted key file next to the script
const KEY_FILE = path.join(__dirname, 'encrypted_wallet_key.bin');

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
function loadKey(password) {
  if (fs.existsSync(KEY_FILE)) {
    const data = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
    return decryptKey(data, password);
  } else {
    console.log('Key not found. Create a wallet using the "create-wallet" command.');
    process.exit(1);
  }
}

// Prompt user for password if not provided via argument
async function getPassword(commandOpts) {
  if (commandOpts.password) {
    return commandOpts.password;
  }
  return new Promise((resolve) => {
    rl.question('Enter password: ', (answer) => {
      resolve(answer);
    });
  });
}

// Configure commands using commander
program
  .version('1.0.0')
  .option('-p, --password <password>', 'Password to decrypt the key');

program
  .command('create-wallet')
  .description('Create a new wallet')
  .action(async () => {
    console.log('Creating a new wallet...');
    const password = await getPassword(program.opts());
    // Your wallet creation logic goes here
    const walletKey = 'example-wallet-key'; // Example key, replace with real one
    const encrypted = encryptKey(walletKey, password);
    fs.writeFileSync(KEY_FILE, JSON.stringify(encrypted));
    console.log('Wallet created, key saved to', KEY_FILE);
    rl.close();
  });

program
  .command('import-wallet')
  .description('Import an existing wallet')
  .action(async () => {
    console.log('Importing wallet...');
    // Your wallet import logic goes here
    rl.close();
  });

program
  .command('show-addresses')
  .description('Show wallet addresses')
  .action(async () => {
    const password = await getPassword(program.opts());
    const key = loadKey(password);
    console.log('Showing addresses for key:', key);
    // Your address display logic goes here
    rl.close();
  });

program
  .command('create-order')
  .description('Create an order')
  .action(async () => {
    const password = await getPassword(program.opts());
    const key = loadKey(password);
    console.log('Creating order with key:', key);
    // Your order creation logic goes here
    rl.close();
  });

program
  .command('cancel-order')
  .description('Cancel an order')
  .action(async () => {
    const password = await getPassword(program.opts());
    const key = loadKey(password);
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
