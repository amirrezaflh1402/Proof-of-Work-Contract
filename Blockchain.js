const crypto = require('crypto');
const uuid = require('uuid');
/**
 * Block represents a block in the blockchain
 */
class Block {
    constructor(index, transactions, prevHash, nonce, hash, timestamp, merkleRoot) {
        this.index = index; // Index of the block in the blockchain
        this.timestamp = timestamp; // Timestamp when the block was created
        this.transactions = transactions; // List of transactions included in the block
        this.prevHash = prevHash; // Hash of the previous block in the chain
        this.hash = hash; // Hash of the current block
        this.nonce = nonce; // Nonce used for the proof of work
        this.merkleRoot = merkleRoot; // Merkle root of the transactions
    }
}

/**
 * Represents a transaction in the blockchain.
 * 
 * A transaction consists of an amount being transferred from a sender to a recipient.
 * Each transaction is uniquely identified by a transaction ID (tx_id).
 */
class Transaction {
    constructor(amount, sender, recipient, privateKey) {
        this.amount = amount; // Amount of currency being transferred
        this.sender = sender; // Address of the sender
        this.recipient = recipient; // Address of the recipient
        this.tx_id = uuid.v4().split('-').join(''); // Unique transaction ID
        this.signature = this.signTransaction(privateKey); // Signature of the transaction
    }

    /**
     * Signs the transaction using the sender's private key.
     * 
     * @privateKey - The private key of the sender.
     * @returns - The signature of the transaction.
     */
    signTransaction(privateKey) {
        const data = Buffer.from(this.tx_id + this.amount + this.sender + this.recipient);
        return crypto.sign(null, data, privateKey).toString('hex');
    }

    /**
     * Verifies the transaction signature using the sender's public key.
     * 
     * @publicKey - The public key of the sender.
     * @returns - Returns true if the signature is valid, otherwise false.
     */
    verifySignature(publicKey) {
        if (!this.signature) return false;

        const data = Buffer.from(this.tx_id + this.amount + this.sender + this.recipient);
        const signatureBuffer = Buffer.from(this.signature, 'hex');

        return crypto.verify(null, data, publicKey, signatureBuffer);
    }

}

/**
 * Represents the entire blockchain with the
 * ability to create transactions, mine and validate
 * all blocks.
 */
class Blockchain {
    constructor(initialDifficulty = 4) {
        this.chain = []; // Array to store the blocks in the blockchain
        this.pendingTransactions = []; // Array to store the pending transactions
        this.difficulty = initialDifficulty; // Initial difficulty level for mining
        this.createGenesisBlock(); // Create the genesis block
    }

    /**
     * Creates a new transaction and adds it to the list of pending transactions.
     * 
     * @sender - The address of the sender.
     * @recipient - The address of the recipient.
     * @amount - The amount of currency being transferred.
     * @privateKey - The private key of the sender.
     */
    createTransaction(sender, recipient, amount, privateKey) {
        const transaction = new Transaction(amount, sender, recipient, privateKey);
        this.pendingTransactions.push(transaction);
    }

    /**
     * Creates the genesis block for the blockchain if the chain is empty.
     * The genesis block is the first block in the blockchain and is created with predefined values.
     */
    createGenesisBlock() {
        if (this.chain.length === 0) {
            const genesisBlock = new Block(0, [], '0', 0, this.getHash('0', [], 0), Math.floor(Date.now() / 1000), null);
            this.chain.push(genesisBlock);
        }
    }

    /**
     * Adds a new block to the blockchain.
     *
     * It creates a new block with the given nonce, calculates its hash,
     * and appends it to the blockchain. It also clears the list of pending transactions
     * and adjusts the mining difficulty after every specified number of blocks.
     *
     * @nonce - The nonce value used to generate the block's hash.
     */
    addBlock(nonce) {
        let index = this.chain.length;
        let blocksBeforeDifficultyIncrease = 10;
        let prevHash = this.chain[this.chain.length - 1].hash;
        let merkleRoot = constructMerkleTree(this.pendingTransactions.map(tx => tx.tx_id + tx.amount + tx.sender + tx.recipient));
        let hash = this.getHash(prevHash, merkleRoot, nonce);
        let timestamp = Math.floor(Date.now() / 1000);
        let block = new Block(index, this.pendingTransactions, prevHash, nonce, hash, timestamp, merkleRoot);

        this.pendingTransactions = [];
        this.chain.push(block);

        if (this.chain.length % blocksBeforeDifficultyIncrease === 0) {
            this.adjustDifficulty();
        }
    }

    /**
     * Generates a SHA-256 hash based on the previous hash, Merkle root, and a nonce.
     *
     * @prevHash - The hash of the previous block.
     * @merkleRoot - The Merkle root of the transactions.
     * @nonce - A nonce value used to vary the hash output.
     * @returns - The resulting SHA-256 hash as a hexadecimal string.
     */
    getHash(prevHash, merkleRoot, nonce) {
        let encrypt = prevHash + merkleRoot + nonce;
        return crypto.createHash('sha256').update(encrypt).digest('hex');
    }

    /**
     * Generates a new target for the blockchain proof of work algorithm based on the difficulty.
     * 
     * The target is a hexadecimal string that represents the maximum allowable hash value for a block to be considered valid.
     * The difficulty level determines the number of leading zeros in the target, making it harder to find a valid hash as the difficulty increases.
     *
     * @difficulty - The difficulty level, which determines the number of leading zeros in the target.
     * @returns - The newly generated target as a hexadecimal string.
     */
    generateTarget(difficulty = this.difficulty) {
        let newTarget;
        let newPrefix = '0'.repeat(difficulty);
        let remainingLength = 64 - difficulty;
        let randomSuffix = crypto.randomBytes(remainingLength).toString('hex').slice(0, remainingLength);
        newTarget = newPrefix + randomSuffix;
        return newTarget;
    }

    /**
     * Executes the Proof of Work algorithm to find a valid nonce.
     * 
     * The Proof of Work algorithm is used to find a nonce value that, when hashed with the previous block's hash and the pending transactions,
     * produces a hash that meets the network's difficulty target. This process involves repeatedly hashing the data with incrementing nonce values
     * until a hash less than or equal to the target is found.
     * 
     * @returns - The valid nonce value.
     */
    proofOfWork() {
        let nonce = 0;
        let prevHash = this.chain[this.chain.length - 1].hash;
        let merkleRoot = constructMerkleTree(this.pendingTransactions.map(tx => tx.tx_id + tx.amount + tx.sender + tx.recipient));
        let target = this.generateTarget();
        while (true) {
            let hash = this.getHash(prevHash, merkleRoot, nonce);
            if (hash <= target) {
                return { nonce };
            }
            nonce++;
        }
    }

    /**
     * Adjusts the mining difficulty of the blockchain based on the average time taken to mine recent blocks.
     * 
     * The function calculates the average time per block by iterating through the blockchain and summing the time differences
     * between consecutive blocks. If the average time per block is less than the expected time per block, the difficulty is increased.
     * If the average time per block is greater than the expected time per block, the difficulty is decreased, but it will not go below 1.
     * 
     * The expected time per block is set to 2.5 seconds, and the adjustment factor is set to 1.
     */
    adjustDifficulty() {
        const expectedTimePerBlock = 2.5;
        const adjustmentFactor = 1;

        if (this.chain.length >= 2) {
            let totalMiningTime = 0;
            for (let i = 1; i < this.chain.length; i++) {
                totalMiningTime += this.chain[i].timestamp - this.chain[i - 1].timestamp;
            }
            const averageTimePerBlock = totalMiningTime / (this.chain.length - 1);

            if (averageTimePerBlock < expectedTimePerBlock) {
                this.difficulty += adjustmentFactor;
            }
            if (averageTimePerBlock > expectedTimePerBlock) {
                this.difficulty -= adjustmentFactor;
                if (this.difficulty < 1) this.difficulty = 1;
            }
        }
    }

    /**
     * Mines a new block by performing the proof of work algorithm and add it to the chain.
     */
    mine() {
        let { nonce } = this.proofOfWork();
        this.addBlock(nonce);
    }

    /**
     * Calculates the average hash rate of the blockchain.
     * 
     * The average hash rate is determined by dividing the total number of hashes attempted
     * by the total time taken to mine all blocks in the chain, excluding the genesis block.
     * 
     * @returns - The average hash rate of the blockchain. Returns 0 if the chain length is 1 or less.
     */
    getAverageHashRate() {
        if (this.chain.length <= 1) return 0;
        let totalHashesAttempted = 0;
        let totalTimeTaken = 0;

        for (let i = 1; i < this.chain.length; i++) {
            totalHashesAttempted += this.chain[i].nonce;
            totalTimeTaken += this.chain[i].timestamp - this.chain[0].timestamp;
        }

        return totalTimeTaken > 0 ? totalHashesAttempted / totalTimeTaken : 0;
    }

    /**
     * Validates the Merkle root of a block by reconstructing the Merkle tree from the block's transactions
     * and comparing the resulting root with the stored Merkle root.
     * 
     * @block - The block whose Merkle root needs to be validated.
     * @returns - Returns true if the Merkle root is valid, otherwise false.
     */
    validateMerkleRoot(block) {
        const reconstructedMerkleRoot = constructMerkleTree(block.transactions.map(tx => tx.tx_id + tx.amount + tx.sender + tx.recipient));
        return block.merkleRoot === reconstructedMerkleRoot;
    }

    /**
     * Validates the blockchain by checking the integrity of each block and its transactions.
     *
     * @returns - Returns true if the blockchain is valid, otherwise false.
     * @returns - Returns false if the genesis block hash is invalid.
     * @returns - Returns false if any block hash is invalid.
     * @returns - Returns false if any block has an invalid Merkle root.
     * @returns - Returns false if any transaction has an invalid signature.
     */
    chainIsValid() {
        for (let i = 0; i < this.chain.length; i++) {
            if (i === 0 && this.chain[i].hash !== this.getHash('0', [], '0')) {
                console.log("Invalid hash in genesis block.");
                return false;
            }
            if (!this.validateMerkleRoot(this.chain[i])) {
                console.log("Invalid Merkle root in block.");
                return false;
            }
            if (i > 0 && this.chain[i].hash !== this.getHash(this.chain[i].prevHash, this.chain[i].merkleRoot, this.chain[i].nonce)) {
                console.log("Invalid hash in block.");
                return false;
            }
            for (let n = 0; n < this.chain[i].transactions.length; n++) {
                if (!this.chain[i].transactions[n].verifySignature(publicKey)) {
                    console.log("Invalid signature in transaction.");
                    return false;
                }
            }
        }
        return true;
    }
}

/**
 * Constructs a Merkle Tree from an array of transactions and returns the root hash.
 * 
 * This function recursively combines pairs of transaction hashes, hashing their concatenation, until a single root hash is obtained.
 * 
 * @transactions - An array of transaction hashes to build the Merkle Tree from.
 * @returns - The root hash of the Merkle Tree, or null if the input array is empty.
 */
function constructMerkleTree(transactions) {
    if (transactions.length === 0) { return null };
    if (transactions.length === 1) {
        return transactions[0];
    }
    transactions = transactions.sort();
    let newLevel = [];
    for (let i = 0; i < transactions.length; i += 2) {
        let left = transactions[i];
        let right = transactions[i + 1] || transactions[i];
        let hash = crypto.createHash('sha256').update(left + right).digest('hex');
        newLevel.push(hash);
    }

    return constructMerkleTree(newLevel);
}

/**
 * Generates a pair of Ed25519 keys (private and public) for signing transactions.
 * 
 * The keys are generated using the Ed25519 algorithm.
 * The private key is used for signing transactions, while the public key is used for verifying signatures.
 * 
 * @returns - An object containing the generated private and public keys.
 */
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

const SimulationType = {
    FAKE_BLOCK: 'FAKE_BLOCK',
    FAKE_MERKLE_ROOT: 'FAKE_MERKLE_ROOT',
    FAKE_SIGNATURE: 'FAKE_SIGNATURE'
};

function simulateChain(blockchain, numTxs, numBlocks, simulationType) {
    for (let i = 0; i < numBlocks; i++) {
        let numTxsRand = Math.floor(Math.random() * Math.floor(numTxs));
        let percentCompleted = (i / numBlocks * 100).toFixed(0);
        for (let j = 0; j < numTxsRand; j++) {
            let sender = uuid.v4().substr(0, 5);
            let receiver = uuid.v4().substr(0, 5);
            blockchain.createTransaction(sender, receiver, Math.floor(Math.random() * Math.floor(1000)), privateKey);
        }
        console.clear();
        console.log(`Simulating [${"█".repeat(i).padEnd(numBlocks + 1, ' ')}] (${percentCompleted}%) - Current Difficulty: ${blockchain.difficulty}`);
        blockchain.mine();
    }

    switch (simulationType) {
        case SimulationType.FAKE_BLOCK:
            blockchain.chain[1].hash = 'fakehash';
            break;
        case SimulationType.FAKE_MERKLE_ROOT:
            blockchain.chain[2].merkleRoot = 'fakemerkleroot';
            break;
        case SimulationType.FAKE_SIGNATURE:
            blockchain.chain[2].transactions[0].signature = 'fakesignature';
            break;
        default:
            console.log('No simulation type selected');
    }
}

const BChain = new Blockchain();
simulateChain(BChain, 5, 3, "");
console.dir(BChain, { depth: null });
console.log("******** Validity of this blockchain: ", BChain.chainIsValid());
console.log("******** Average Hash Rate: ", BChain.getAverageHashRate(), "hashes per second");

module.exports = Blockchain;
