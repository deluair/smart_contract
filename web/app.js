// Global variables
let currentUser = null;
let authToken = null;
let wallets = [];
let priceData = {};
let marketData = {};

// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadInitialData();
});

// Initialize application
function initializeApp() {
    // Check for stored auth token
    const storedToken = localStorage.getItem('authToken');
    const storedUser = localStorage.getItem('currentUser');
    
    if (storedToken && storedUser) {
        authToken = storedToken;
        currentUser = JSON.parse(storedUser);
        updateAuthUI(true);
    }
    
    // Show dashboard by default
    showSection('dashboard');
}

// Setup event listeners
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const section = this.getAttribute('data-section');
            showSection(section);
            
            // Update active nav link
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Wallet type change
    const walletTypeSelect = document.getElementById('walletType');
    if (walletTypeSelect) {
        walletTypeSelect.addEventListener('change', function() {
            const multisigOptions = document.getElementById('multisigOptions');
            if (this.value === 'multisig') {
                multisigOptions.style.display = 'block';
            } else {
                multisigOptions.style.display = 'none';
            }
        });
    }
    
    // Swap token inputs
    const swapFromAmount = document.getElementById('swapFromAmount');
    if (swapFromAmount) {
        swapFromAmount.addEventListener('input', calculateSwapAmount);
    }
    
    // Modal close on outside click
    window.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            e.target.classList.remove('show');
        }
    });
}

// Load initial data
function loadInitialData() {
    loadBlockchainInfo();
    loadMarketData();
    loadPriceFeeds();
    
    if (authToken) {
        loadUserWallets();
        loadUserTransactions();
    }
}

// Authentication functions
function showLogin() {
    document.getElementById('loginModal').classList.add('show');
}

function showRegister() {
    document.getElementById('registerModal').classList.add('show');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('show');
}

async function login() {
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!username || !password) {
        showToast('Please enter username and password', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            authToken = data.token;
            currentUser = { username };
            
            localStorage.setItem('authToken', authToken);
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            
            updateAuthUI(true);
            closeModal('loginModal');
            showToast('Login successful!', 'success');
            
            // Load user data
            loadUserWallets();
            loadUserTransactions();
        } else {
            showToast(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showToast('Login failed. Please try again.', 'error');
    } finally {
        showLoading(false);
    }
}

async function register() {
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    
    if (!username || !email || !password) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            closeModal('registerModal');
            showToast('Registration successful! Please login.', 'success');
            showLogin();
        } else {
            showToast(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showToast('Registration failed. Please try again.', 'error');
    } finally {
        showLoading(false);
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    wallets = [];
    
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    
    updateAuthUI(false);
    showToast('Logged out successfully', 'success');
    
    // Clear user-specific data
    document.getElementById('walletList').innerHTML = '';
    document.getElementById('transactionList').innerHTML = '';
}

function updateAuthUI(isLoggedIn) {
    const userInfo = document.getElementById('userInfo');
    const authButtons = document.getElementById('authButtons');
    const userName = document.getElementById('userName');
    
    if (isLoggedIn && currentUser) {
        userInfo.style.display = 'flex';
        authButtons.style.display = 'none';
        userName.textContent = currentUser.username;
    } else {
        userInfo.style.display = 'none';
        authButtons.style.display = 'flex';
    }
}

// Navigation functions
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show selected section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
        
        // Load section-specific data
        switch(sectionId) {
            case 'dashboard':
                loadDashboardData();
                break;
            case 'wallet':
                loadWalletData();
                break;
            case 'trading':
                loadTradingData();
                break;
            case 'lending':
                loadLendingData();
                break;
            case 'derivatives':
                loadDerivativesData();
                break;
            case 'oracles':
                loadOracleData();
                break;
        }
    }
}

// Data loading functions
async function loadBlockchainInfo() {
    try {
        const response = await fetch(`${API_BASE_URL}/blockchain/info`);
        const data = await response.json();
        
        if (data.chain_length !== undefined) {
            document.getElementById('blockHeight').textContent = data.chain_length;
        }
    } catch (error) {
        console.error('Error loading blockchain info:', error);
    }
}

async function loadMarketData() {
    try {
        const response = await fetch(`${API_BASE_URL}/market/data`);
        const data = await response.json();
        
        marketData = data;
        
        if (data.oracle_stats) {
            document.getElementById('activeOracles').textContent = data.oracle_stats.active_oracles || 0;
        }
    } catch (error) {
        console.error('Error loading market data:', error);
    }
}

async function loadPriceFeeds() {
    const symbols = ['BTC', 'ETH', 'USDC', 'DAI'];
    const priceList = document.getElementById('priceList');
    
    if (!priceList) return;
    
    priceList.innerHTML = '';
    
    for (const symbol of symbols) {
        try {
            const response = await fetch(`${API_BASE_URL}/oracle/price/${symbol}`);
            const data = await response.json();
            
            if (data.price) {
                priceData[symbol] = data;
                
                const priceItem = document.createElement('div');
                priceItem.className = 'price-item';
                priceItem.innerHTML = `
                    <span class="price-symbol">${symbol}</span>
                    <div>
                        <span class="price-value">$${parseFloat(data.price).toLocaleString()}</span>
                        <span class="price-change positive">+2.5%</span>
                    </div>
                `;
                priceList.appendChild(priceItem);
            }
        } catch (error) {
            console.error(`Error loading price for ${symbol}:`, error);
        }
    }
}

async function loadUserWallets() {
    if (!authToken) return;
    
    // This would typically load user's existing wallets
    // For now, we'll populate the from address dropdown with any created wallets
    const fromAddressSelect = document.getElementById('fromAddress');
    if (fromAddressSelect) {
        fromAddressSelect.innerHTML = '<option value="">Select wallet...</option>';
        
        wallets.forEach(wallet => {
            const option = document.createElement('option');
            option.value = wallet.address;
            option.textContent = `${wallet.type} - ${wallet.address.substring(0, 10)}...`;
            fromAddressSelect.appendChild(option);
        });
    }
}

async function loadUserTransactions() {
    if (!authToken) return;
    
    const transactionList = document.getElementById('transactionList');
    if (!transactionList) return;
    
    // Mock transaction data for demonstration
    const mockTransactions = [
        {
            hash: '0x1234...5678',
            amount: '0.5 ETH',
            type: 'Send',
            timestamp: new Date().toLocaleString()
        },
        {
            hash: '0x9876...5432',
            amount: '100 USDC',
            type: 'Receive',
            timestamp: new Date(Date.now() - 3600000).toLocaleString()
        }
    ];
    
    transactionList.innerHTML = '';
    
    mockTransactions.forEach(tx => {
        const txItem = document.createElement('div');
        txItem.className = 'transaction-item';
        txItem.innerHTML = `
            <div class="transaction-info">
                <div class="transaction-hash">${tx.hash}</div>
                <div>${tx.type} - ${tx.timestamp}</div>
            </div>
            <div class="transaction-amount">${tx.amount}</div>
        `;
        transactionList.appendChild(txItem);
    });
}

// Section-specific data loading
function loadDashboardData() {
    loadBlockchainInfo();
    loadMarketData();
    loadPriceFeeds();
    if (authToken) {
        loadUserTransactions();
    }
}

function loadWalletData() {
    if (authToken) {
        loadUserWallets();
    }
}

function loadTradingData() {
    loadLiquidityPools();
}

function loadLendingData() {
    loadSupplyAssets();
    loadBorrowStats();
}

function loadDerivativesData() {
    loadActivePositions();
}

function loadOracleData() {
    loadOracleFeeds();
    loadOracleNodes();
}

// Wallet functions
async function createWallet() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const walletType = document.getElementById('walletType').value;
    const requestData = { type: walletType };
    
    if (walletType === 'multisig') {
        const requiredSigs = parseInt(document.getElementById('requiredSigs').value);
        const publicKeys = document.getElementById('publicKeys').value
            .split('\n')
            .map(key => key.trim())
            .filter(key => key.length > 0);
        
        if (publicKeys.length < requiredSigs) {
            showToast('Not enough public keys for required signatures', 'error');
            return;
        }
        
        requestData.required_signatures = requiredSigs;
        requestData.public_keys = publicKeys;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch(`${API_BASE_URL}/wallet`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(requestData)
        });
        
        const data = await response.json();
        
        if (data.success) {
            wallets.push(data);
            showToast(`${walletType} wallet created successfully!`, 'success');
            
            // Display wallet info
            displayWalletInfo(data);
            loadUserWallets();
        } else {
            showToast(data.error || 'Failed to create wallet', 'error');
        }
    } catch (error) {
        console.error('Wallet creation error:', error);
        showToast('Failed to create wallet', 'error');
    } finally {
        showLoading(false);
    }
}

function displayWalletInfo(walletData) {
    const walletList = document.getElementById('walletList');
    if (!walletList) return;
    
    const walletItem = document.createElement('div');
    walletItem.className = 'wallet-item fade-in';
    walletItem.innerHTML = `
        <div class="wallet-info">
            <div><strong>${walletData.wallet_type.toUpperCase()} Wallet</strong></div>
            <div class="wallet-address">${walletData.address}</div>
            ${walletData.mnemonic ? `<div><small>Mnemonic: ${walletData.mnemonic}</small></div>` : ''}
        </div>
        <div class="wallet-balance">$0.00</div>
    `;
    
    walletList.appendChild(walletItem);
}

async function sendTransaction() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const fromAddress = document.getElementById('fromAddress').value;
    const toAddress = document.getElementById('toAddress').value;
    const amount = document.getElementById('amount').value;
    const fee = document.getElementById('fee').value;
    const privateKey = document.getElementById('privateKey').value;
    
    if (!fromAddress || !toAddress || !amount || !privateKey) {
        showToast('Please fill in all required fields', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        const response = await fetch(`${API_BASE_URL}/blockchain/transaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                sender: fromAddress,
                recipient: toAddress,
                amount: parseFloat(amount),
                fee: parseFloat(fee),
                private_key: privateKey
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Transaction sent successfully!', 'success');
            
            // Clear form
            document.getElementById('toAddress').value = '';
            document.getElementById('amount').value = '';
            document.getElementById('privateKey').value = '';
            
            // Reload transactions
            loadUserTransactions();
        } else {
            showToast(data.error || 'Transaction failed', 'error');
        }
    } catch (error) {
        console.error('Transaction error:', error);
        showToast('Transaction failed', 'error');
    } finally {
        showLoading(false);
    }
}

// Trading functions
function calculateSwapAmount() {
    const fromAmount = parseFloat(document.getElementById('swapFromAmount').value) || 0;
    const fromToken = document.getElementById('swapFromToken').value;
    const toToken = document.getElementById('swapToToken').value;
    
    // Mock exchange rate calculation
    let rate = 1;
    if (fromToken === 'ETH' && toToken === 'USDC') {
        rate = 2000;
    } else if (fromToken === 'USDC' && toToken === 'ETH') {
        rate = 0.0005;
    }
    
    const toAmount = fromAmount * rate;
    document.getElementById('swapToAmount').value = toAmount.toFixed(6);
    
    // Update exchange rate display
    document.getElementById('exchangeRate').textContent = `1 ${fromToken} = ${rate} ${toToken}`;
}

function swapTokens() {
    const fromToken = document.getElementById('swapFromToken').value;
    const toToken = document.getElementById('swapToToken').value;
    const fromAmount = document.getElementById('swapFromAmount').value;
    const toAmount = document.getElementById('swapToAmount').value;
    
    // Swap the tokens
    document.getElementById('swapFromToken').value = toToken;
    document.getElementById('swapToToken').value = fromToken;
    document.getElementById('swapFromAmount').value = toAmount;
    document.getElementById('swapToAmount').value = fromAmount;
    
    calculateSwapAmount();
}

async function executeSwap() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const fromAmount = document.getElementById('swapFromAmount').value;
    const fromToken = document.getElementById('swapFromToken').value;
    const toToken = document.getElementById('swapToToken').value;
    
    if (!fromAmount || fromAmount <= 0) {
        showToast('Please enter a valid amount', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Mock swap execution
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        showToast(`Swapped ${fromAmount} ${fromToken} for ${toToken}`, 'success');
        
        // Clear form
        document.getElementById('swapFromAmount').value = '';
        document.getElementById('swapToAmount').value = '';
    } catch (error) {
        console.error('Swap error:', error);
        showToast('Swap failed', 'error');
    } finally {
        showLoading(false);
    }
}

function loadLiquidityPools() {
    const poolList = document.getElementById('poolList');
    if (!poolList) return;
    
    const mockPools = [
        { pair: 'ETH/USDC', liquidity: '$1,234,567', apr: '12.5%' },
        { pair: 'DAI/USDC', liquidity: '$987,654', apr: '8.3%' },
        { pair: 'ETH/DAI', liquidity: '$654,321', apr: '15.7%' }
    ];
    
    poolList.innerHTML = '';
    
    mockPools.forEach(pool => {
        const poolItem = document.createElement('div');
        poolItem.className = 'pool-item';
        poolItem.innerHTML = `
            <div>
                <strong>${pool.pair}</strong>
                <div>Liquidity: ${pool.liquidity}</div>
            </div>
            <div>
                <div>APR: ${pool.apr}</div>
                <button class="btn-primary" style="margin-top: 0.5rem; padding: 0.25rem 0.75rem; font-size: 0.8rem;">Add</button>
            </div>
        `;
        poolList.appendChild(poolItem);
    });
}

async function addLiquidity() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const amountA = document.getElementById('liquidityAmountA').value;
    const amountB = document.getElementById('liquidityAmountB').value;
    const tokenA = document.getElementById('liquidityTokenA').value;
    const tokenB = document.getElementById('liquidityTokenB').value;
    
    if (!amountA || !amountB || amountA <= 0 || amountB <= 0) {
        showToast('Please enter valid amounts', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Mock liquidity addition
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        showToast(`Added liquidity: ${amountA} ${tokenA} + ${amountB} ${tokenB}`, 'success');
        
        // Clear form
        document.getElementById('liquidityAmountA').value = '';
        document.getElementById('liquidityAmountB').value = '';
        
        loadLiquidityPools();
    } catch (error) {
        console.error('Add liquidity error:', error);
        showToast('Failed to add liquidity', 'error');
    } finally {
        showLoading(false);
    }
}

// Lending functions
function loadSupplyAssets() {
    const assetList = document.getElementById('supplyAssets');
    if (!assetList) return;
    
    const mockAssets = [
        { symbol: 'ETH', supplied: '0.0', apy: '4.2%' },
        { symbol: 'USDC', supplied: '0.0', apy: '3.8%' },
        { symbol: 'DAI', supplied: '0.0', apy: '3.5%' }
    ];
    
    assetList.innerHTML = '';
    
    mockAssets.forEach(asset => {
        const assetItem = document.createElement('div');
        assetItem.className = 'asset-item';
        assetItem.innerHTML = `
            <div>
                <strong>${asset.symbol}</strong>
                <div>Supplied: ${asset.supplied}</div>
            </div>
            <div>
                <div>APY: ${asset.apy}</div>
            </div>
        `;
        assetList.appendChild(assetItem);
    });
}

function loadBorrowStats() {
    // Mock borrow statistics
    document.getElementById('collateralValue').textContent = '$0.00';
    document.getElementById('borrowedValue').textContent = '$0.00';
    document.getElementById('healthFactor').textContent = '∞';
}

async function supplyAsset() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const asset = document.getElementById('supplyAsset').value;
    const amount = document.getElementById('supplyAmount').value;
    
    if (!amount || amount <= 0) {
        showToast('Please enter a valid amount', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Mock supply operation
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        showToast(`Supplied ${amount} ${asset}`, 'success');
        
        document.getElementById('supplyAmount').value = '';
        loadSupplyAssets();
        loadBorrowStats();
    } catch (error) {
        console.error('Supply error:', error);
        showToast('Failed to supply asset', 'error');
    } finally {
        showLoading(false);
    }
}

async function borrowAsset() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const asset = document.getElementById('borrowAsset').value;
    const amount = document.getElementById('borrowAmount').value;
    
    if (!amount || amount <= 0) {
        showToast('Please enter a valid amount', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Mock borrow operation
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        showToast(`Borrowed ${amount} ${asset}`, 'success');
        
        document.getElementById('borrowAmount').value = '';
        loadBorrowStats();
    } catch (error) {
        console.error('Borrow error:', error);
        showToast('Failed to borrow asset', 'error');
    } finally {
        showLoading(false);
    }
}

// Derivatives functions
function loadActivePositions() {
    const positionsList = document.getElementById('positionsList');
    if (!positionsList) return;
    
    const mockPositions = [
        {
            type: 'Call Option',
            asset: 'ETH',
            strike: '$2000',
            expiry: '2024-03-15',
            pnl: '+$125.50'
        },
        {
            type: 'Put Option',
            asset: 'BTC',
            strike: '$45000',
            expiry: '2024-02-28',
            pnl: '-$75.25'
        }
    ];
    
    positionsList.innerHTML = '';
    
    mockPositions.forEach(position => {
        const positionItem = document.createElement('div');
        positionItem.className = 'position-item';
        positionItem.innerHTML = `
            <div>
                <strong>${position.type}</strong>
                <div>${position.asset} - Strike: ${position.strike}</div>
                <div>Expires: ${position.expiry}</div>
            </div>
            <div>
                <div class="${position.pnl.startsWith('+') ? 'text-green' : 'text-red'}">
                    ${position.pnl}
                </div>
                <button class="btn-secondary" style="margin-top: 0.5rem; padding: 0.25rem 0.75rem; font-size: 0.8rem;">Close</button>
            </div>
        `;
        positionsList.appendChild(positionItem);
    });
}

async function createOption() {
    if (!authToken) {
        showToast('Please login first', 'error');
        return;
    }
    
    const asset = document.getElementById('optionAsset').value;
    const optionType = document.getElementById('optionType').value;
    const strikePrice = document.getElementById('strikePrice').value;
    const expiryDate = document.getElementById('expiryDate').value;
    const premium = document.getElementById('premium').value;
    
    if (!strikePrice || !expiryDate || !premium) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Mock option creation
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        showToast(`Created ${optionType} option for ${asset}`, 'success');
        
        // Clear form
        document.getElementById('strikePrice').value = '';
        document.getElementById('expiryDate').value = '';
        document.getElementById('premium').value = '';
        
        loadActivePositions();
    } catch (error) {
        console.error('Option creation error:', error);
        showToast('Failed to create option', 'error');
    } finally {
        showLoading(false);
    }
}

// Oracle functions
function loadOracleFeeds() {
    const oracleFeeds = document.getElementById('oracleFeeds');
    if (!oracleFeeds) return;
    
    const mockFeeds = [
        { symbol: 'BTC/USD', price: '$43,250.00', updated: '2 min ago', status: 'active' },
        { symbol: 'ETH/USD', price: '$2,650.00', updated: '1 min ago', status: 'active' },
        { symbol: 'USDC/USD', price: '$1.00', updated: '30 sec ago', status: 'active' },
        { symbol: 'DAI/USD', price: '$0.999', updated: '45 sec ago', status: 'active' }
    ];
    
    oracleFeeds.innerHTML = '';
    
    mockFeeds.forEach(feed => {
        const feedItem = document.createElement('div');
        feedItem.className = 'oracle-feed-item';
        feedItem.innerHTML = `
            <div>
                <strong>${feed.symbol}</strong>
                <div>Updated: ${feed.updated}</div>
            </div>
            <div>
                <div>${feed.price}</div>
                <span class="node-status ${feed.status}">${feed.status}</span>
            </div>
        `;
        oracleFeeds.appendChild(feedItem);
    });
}

function loadOracleNodes() {
    const oracleNodes = document.getElementById('oracleNodes');
    if (!oracleNodes) return;
    
    const mockNodes = [
        { id: 'oracle-001', reputation: '98.5%', status: 'active', responses: '1,234' },
        { id: 'oracle-002', reputation: '97.2%', status: 'active', responses: '987' },
        { id: 'oracle-003', reputation: '95.8%', status: 'inactive', responses: '756' },
        { id: 'oracle-004', reputation: '99.1%', status: 'active', responses: '2,145' }
    ];
    
    oracleNodes.innerHTML = '';
    
    mockNodes.forEach(node => {
        const nodeItem = document.createElement('div');
        nodeItem.className = 'oracle-node-item';
        nodeItem.innerHTML = `
            <div>
                <strong>${node.id}</strong>
                <div>Reputation: ${node.reputation}</div>
                <div>Responses: ${node.responses}</div>
            </div>
            <span class="node-status ${node.status}">${node.status}</span>
        `;
        oracleNodes.appendChild(nodeItem);
    });
}

// Utility functions
function refreshPrices() {
    loadPriceFeeds();
    showToast('Prices refreshed', 'success');
}

function refreshOracleData() {
    loadOracleFeeds();
    loadOracleNodes();
    showToast('Oracle data refreshed', 'success');
}

function showLoading(show) {
    const spinner = document.getElementById('loadingSpinner');
    if (spinner) {
        spinner.style.display = show ? 'flex' : 'none';
    }
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div>${message}</div>
        <button onclick="this.parentElement.remove()" style="background: none; border: none; color: inherit; cursor: pointer; margin-left: 1rem;">&times;</button>
    `;
    
    toastContainer.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, 5000);
}

// Error handling
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
    showToast('An unexpected error occurred', 'error');
});

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
    showToast('An unexpected error occurred', 'error');
    e.preventDefault();
});

// Export functions for global access
window.showLogin = showLogin;
window.showRegister = showRegister;
window.closeModal = closeModal;
window.login = login;
window.register = register;
window.logout = logout;
window.createWallet = createWallet;
window.sendTransaction = sendTransaction;
window.swapTokens = swapTokens;
window.executeSwap = executeSwap;
window.addLiquidity = addLiquidity;
window.supplyAsset = supplyAsset;
window.borrowAsset = borrowAsset;
window.createOption = createOption;
window.refreshPrices = refreshPrices;
window.refreshOracleData = refreshOracleData;