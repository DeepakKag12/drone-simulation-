/**
 * Shamir Secret Sharing - Animated Canvas Implementation
 * Visual animation of secret splitting and reconstruction
 */

// ===========================
// Global State
// ===========================
let canvas, ctx;
let animationState = 'idle'; // 'idle', 'splitting', 'shares', 'reconstructing', 'reconstructed'
let animationProgress = 0;
let shares = [];
let selectedShares = [];
let config = {
    secret: 12345,
    k: 3,
    n: 5,
    coefficients: []
};

// Ball/Circle objects
let secretBall = null;
let shareBalls = [];

// ===========================
// Ball Class
// ===========================
class Ball {
    constructor(x, y, radius, color, label, data = null) {
        this.x = x;
        this.y = y;
        this.targetX = x;
        this.targetY = y;
        this.radius = radius;
        this.targetRadius = radius;
        this.color = color;
        this.label = label;
        this.data = data;
        this.selected = false;
        this.alpha = 1;
        this.glowIntensity = 0;
    }

    update(speed = 0.1) {
        // Smooth movement to target position
        this.x += (this.targetX - this.x) * speed;
        this.y += (this.targetY - this.y) * speed;
        this.radius += (this.targetRadius - this.radius) * speed;
        
        // Glow effect
        if (this.selected) {
            this.glowIntensity = Math.min(this.glowIntensity + 0.1, 1);
        } else {
            this.glowIntensity = Math.max(this.glowIntensity - 0.1, 0);
        }
    }

    draw(ctx) {
        ctx.save();
        
        // Glow effect for selected balls
        if (this.glowIntensity > 0) {
            const gradient = ctx.createRadialGradient(
                this.x, this.y, this.radius * 0.5,
                this.x, this.y, this.radius * 1.5
            );
            gradient.addColorStop(0, `rgba(80, 200, 120, ${this.glowIntensity * 0.8})`);
            gradient.addColorStop(1, `rgba(80, 200, 120, 0)`);
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius * 1.5, 0, Math.PI * 2);
            ctx.fill();
        }

        // Main ball
        const gradient = ctx.createRadialGradient(
            this.x - this.radius * 0.3, 
            this.y - this.radius * 0.3, 
            this.radius * 0.1,
            this.x, 
            this.y, 
            this.radius
        );
        gradient.addColorStop(0, this.lightenColor(this.color, 40));
        gradient.addColorStop(1, this.color);
        
        ctx.globalAlpha = this.alpha;
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fill();

        // Border
        ctx.strokeStyle = this.selected ? '#50c878' : 'rgba(255, 255, 255, 0.3)';
        ctx.lineWidth = this.selected ? 3 : 2;
        ctx.stroke();

        // Label (number on top)
        ctx.globalAlpha = 1;
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${this.radius * 0.6}px Inter, Arial`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(this.label, this.x, this.y);

        // Data text below the ball
        if (this.data) {
            ctx.font = `${this.radius * 0.25}px "JetBrains Mono", monospace`;
            ctx.fillStyle = '#f39c12';
            ctx.fillText(this.data, this.x, this.y + this.radius + 20);
        }

        ctx.restore();
    }

    lightenColor(color, percent) {
        const num = parseInt(color.replace("#",""), 16);
        const amt = Math.round(2.55 * percent);
        const R = (num >> 16) + amt;
        const G = (num >> 8 & 0x00FF) + amt;
        const B = (num & 0x0000FF) + amt;
        return "#" + (0x1000000 + (R<255?R<1?0:R:255)*0x10000 +
            (G<255?G<1?0:G:255)*0x100 + (B<255?B<1?0:B:255))
            .toString(16).slice(1);
    }

    contains(px, py) {
        const dx = px - this.x;
        const dy = py - this.y;
        return dx * dx + dy * dy <= this.radius * this.radius;
    }
}

// ===========================
// Animation Functions
// ===========================

function initCanvas() {
    canvas = document.getElementById('animation-canvas');
    ctx = canvas.getContext('2d');
    
    // Set canvas size
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    // Mouse events
    canvas.addEventListener('click', handleCanvasClick);
    
    // Start animation loop
    animate();
}

function resizeCanvas() {
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
}

function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw background particles (optional)
    drawBackgroundParticles();
    
    // Update and draw based on state
    switch (animationState) {
        case 'idle':
            drawIdleState();
            break;
        case 'splitting':
            updateSplitting();
            break;
        case 'shares':
            updateShares();
            break;
        case 'reconstructing':
            updateReconstructing();
            break;
        case 'reconstructed':
            updateReconstructed();
            break;
    }
    
    requestAnimationFrame(animate);
}

function drawBackgroundParticles() {
    // Draw subtle animated particles in background
    const time = Date.now() * 0.001;
    for (let i = 0; i < 30; i++) {
        const x = (Math.sin(time * 0.5 + i) * 0.5 + 0.5) * canvas.width;
        const y = (Math.cos(time * 0.3 + i * 0.5) * 0.5 + 0.5) * canvas.height;
        const size = 2 + Math.sin(time + i) * 1;
        
        ctx.fillStyle = `rgba(74, 144, 226, ${0.2 + Math.sin(time + i) * 0.1})`;
        ctx.beginPath();
        ctx.arc(x, y, size, 0, Math.PI * 2);
        ctx.fill();
    }
}

function drawIdleState() {
    // Show "Ready" message
    ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
    ctx.font = '20px Inter, Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('Click "Split Secret" to begin', canvas.width / 2, canvas.height / 2);
}

function updateSplitting() {
    animationProgress += 0.02;
    
    if (animationProgress <= 1) {
        // Draw the main secret ball shrinking
        if(secretBall) {
            secretBall.update(0.15);
            secretBall.draw(ctx);
        }
        
        // Draw share balls appearing and moving outward
        shareBalls.forEach(ball => {
            ball.alpha = animationProgress;
            ball.update(0.1);
            ball.draw(ctx);
            
            // Draw lines from center to shares
            ctx.strokeStyle = `rgba(74, 144, 226, ${animationProgress * 0.3})`;
            ctx.lineWidth = 2;
            ctx.setLineDash([5, 5]);
            ctx.beginPath();
            ctx.moveTo(secretBall.x, secretBall.y);
            ctx.lineTo(ball.x, ball.y);
            ctx.stroke();
            ctx.setLineDash([]);
        });
    } else {
        // Animation complete
        animationState = 'shares';
        animationProgress = 0;
        updateStatus('Shares created! Click on balls to select them for reconstruction');
        document.getElementById('share-panel').style.display = 'block';
        document.getElementById('reconstruct-btn').style.display = 'inline-flex';
    }
}

function updateShares() {
    // Draw all share balls in their positions
    shareBalls.forEach(ball => {
        ball.update(0.15);
        ball.draw(ctx);
    });
}

function updateReconstructing() {
    animationProgress += 0.015;
    
    if (animationProgress <= 1) {
        // Selected balls move towards center
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;
        
        shareBalls.forEach(ball => {
            ball.update(0.1);
            ball.draw(ctx);
            
            if (ball.selected) {
                // Draw lines from selected balls to center
                ctx.strokeStyle = `rgba(80, 200, 120, ${0.8})`;
                ctx.lineWidth = 3;
                ctx.beginPath();
                ctx.moveTo(ball.x, ball.y);
                ctx.lineTo(centerX, centerY);
                ctx.stroke();
            }
        });
        
        // Draw combining effect at center
        const reconstructRadius = 50 + animationProgress * 50;
        const gradient = ctx.createRadialGradient(
            centerX, centerY, reconstructRadius * 0.3,
            centerX, centerY, reconstructRadius
        );
        gradient.addColorStop(0, `rgba(80, 200, 120, ${animationProgress * 0.8})`);
        gradient.addColorStop(1, `rgba(80, 200, 120, 0)`);
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(centerX, centerY, reconstructRadius, 0, Math.PI * 2);
        ctx.fill();
        
        // Draw secret text emerging
        ctx.fillStyle = `rgba(243, 156, 18, ${animationProgress})`;
        ctx.font = `bold ${30 + animationProgress * 20}px Arial`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(config.secret, centerX, centerY);
        
    } else {
        // Animation complete
        animationState = 'reconstructed';
        animationProgress = 0;
        
        // Create reconstructed ball
        const reconstructedSecret = reconstructSecret();
        secretBall = new Ball(
            canvas.width / 2,
            canvas.height / 2,
            100,
            '#2ecc71',
            config.secret,
            null
        );
        
        const isSuccessfulReconstruction = selectedShares.length >= config.k;
        if (isSuccessfulReconstruction) {
            updateStatus(`Secret reconstructed: ${reconstructedSecret}`);
        } else {
            updateStatus(`Reconstruction failed! Need ${config.k} shares, but only used ${selectedShares.length}`);
        }
        displayResult(reconstructedSecret, isSuccessfulReconstruction);
    }
}

function updateReconstructed() {
    // Show reconstructed secret ball
    if (secretBall) {
        secretBall.update(0.1);
        secretBall.draw(ctx);
        
        // Pulsating effect
        const pulse = Math.sin(Date.now() * 0.003) * 10;
        secretBall.targetRadius = 100 + pulse;
    }
    
    // Draw share balls faded in background
    shareBalls.forEach(ball => {
        ball.alpha = 0.3;
        ball.draw(ctx);
    });
}

// ===========================
// Shamir Algorithm Functions
// ===========================

function generateRandomCoefficient() {
    // Use crypto-quality randomness when available
    if (window.crypto && window.crypto.getRandomValues) {
        const array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        return (array[0] % 9999) + 1; // 1 to 10000
    }
    // Fallback to Math.random with better range
    return Math.floor(Math.random() * 9999) + 1;
}

function evaluatePolynomial(coefficients, x) {
    let result = 0;
    for (let i = 0; i < coefficients.length; i++) {
        result += coefficients[i] * Math.pow(x, i);
    }
    return Math.round(result); // Better precision than Math.floor
}

function lagrangeInterpolation(selectedShares) {
    if (selectedShares.length === 0) {
        throw new Error('No shares provided for interpolation');
    }
    
    // Check for duplicate x values
    const xValues = selectedShares.map(share => share[0]);
    const uniqueX = [...new Set(xValues)];
    if (uniqueX.length !== xValues.length) {
        throw new Error('Duplicate x values in shares');
    }
    
    let secret = 0;
    
    for (let i = 0; i < selectedShares.length; i++) {
        const [xi, yi] = selectedShares[i];
        let numerator = 1;
        let denominator = 1;
        
        for (let j = 0; j < selectedShares.length; j++) {
            if (i !== j) {
                const [xj] = selectedShares[j];
                numerator *= (0 - xj);
                denominator *= (xi - xj);
                
                // Prevent division by zero
                if (denominator === 0) {
                    throw new Error('Division by zero in Lagrange interpolation');
                }
            }
        }
        
        const lagrangeCoefficient = numerator / denominator;
        secret += yi * lagrangeCoefficient;
    }
    
    return Math.round(secret);
}

// Calculate Lagrange coefficient for a specific share
function calculateLagrangeCoefficient(shareIndex, selectedIndices) {
    const xi = shares[shareIndex][0]; // x-value of the share
    let numerator = 1;
    let denominator = 1;
    
    for (let j = 0; j < selectedIndices.length; j++) {
        const otherIndex = selectedIndices[j];
        if (shareIndex !== otherIndex) {
            const xj = shares[otherIndex][0];
            numerator *= (0 - xj); // We want to evaluate at x=0 to get the secret
            denominator *= (xi - xj);
        }
    }
    
    return numerator / denominator;
}

// ===========================
// Main Action Functions
// ===========================

function splitSecret() {
    // Get configuration with better validation
    const secretInput = document.getElementById('secret-input').value;
    const kInput = document.getElementById('k-input').value;
    const nInput = document.getElementById('n-input').value;
    
    // Enhanced validation
    if (!secretInput || !kInput || !nInput) {
        showError('Please fill in all fields!');
        return;
    }
    
    config.secret = parseInt(secretInput);
    config.k = parseInt(kInput);
    config.n = parseInt(nInput);
    
    // Comprehensive validation
    if (isNaN(config.secret) || config.secret <= 0) {
        showError('Secret must be a positive number!');
        return;
    }
    
    if (isNaN(config.k) || isNaN(config.n)) {
        showError('K and N must be valid numbers!');
        return;
    }
    
    if (config.k > config.n) {
        showError('Threshold K cannot be greater than total shares N!');
        return;
    }
    
    if (config.k < 2 || config.n < 2) {
        showError('K and N must be at least 2!');
        return;
    }
    
    if (config.k > 8 || config.n > 8) {
        showError('Maximum 8 shares supported for optimal visualization!');
        return;
    }
    
    if (config.secret > 999999) {
        showError('Secret too large! Please use a smaller number.');
        return;
    }
    
    try {
        // Generate polynomial coefficients
        config.coefficients = [config.secret];
        for (let i = 1; i < config.k; i++) {
            config.coefficients.push(generateRandomCoefficient());
        }
        
        // Generate shares with error handling
        shares = [];
        for (let x = 1; x <= config.n; x++) {
            const y = evaluatePolynomial(config.coefficients, x);
            if (!isFinite(y)) {
                throw new Error('Invalid polynomial evaluation result');
            }
            shares.push([x, y]);
        }
        
        // Clear any previous selections
        selectedShares = [];
        
        // Create ball objects
        createShareBalls();
        
        // Start splitting animation
        animationState = 'splitting';
        animationProgress = 0;
        
updateStatus('Splitting secret into shares...');
        updateShareList();
        
        // Hide result if visible
        document.getElementById('result-section').style.display = 'none';
    } catch (error) {
        showError(`Error generating shares: ${error.message}`);
        console.error('Share generation error:', error);
        return;
    }
}

function createShareBalls() {
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    
    // Create initial secret ball
    secretBall = new Ball(centerX, centerY, 100, '#e74c3c', config.secret, null);
    secretBall.targetRadius = 30; // Shrink during split
    
    // Create share balls
    shareBalls = [];
    const angleStep = (Math.PI * 2) / config.n;
    const radius = Math.min(canvas.width, canvas.height) * 0.35;
    
    for (let i = 0; i < config.n; i++) {
        const angle = i * angleStep - Math.PI / 2; // Start from top
        const x = centerX + Math.cos(angle) * radius;
        const y = centerY + Math.sin(angle) * radius;
        
        const ball = new Ball(
            centerX, centerY, // Start at center
            30,
            '#4a90e2',
            `${i + 1}`,
            `(${shares[i][0]}, ${shares[i][1]})`
        );
        
        ball.targetX = x;
        ball.targetY = y;
        ball.targetRadius = 50;
        ball.shareIndex = i;
        
        shareBalls.push(ball);
    }
}

function handleCanvasClick(event) {
    if (animationState !== 'shares') return;
    
    const rect = canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    
    // Check which ball was clicked
    for (let ball of shareBalls) {
        if (ball.contains(x, y)) {
            toggleShareSelection(ball.shareIndex);
            break;
        }
    }
}

function toggleShareSelection(index) {
    const ball = shareBalls[index];
    
    if (ball.selected) {
        // Deselect
        ball.selected = false;
        selectedShares = selectedShares.filter(i => i !== index);
    } else {
        // Select - allow selecting any number of shares
        if (selectedShares.length < config.n) {
            ball.selected = true;
            selectedShares.push(index);
        } else {
            alert(`All ${config.n} shares are already selected!`);
            return;
        }
    }
    
    updateShareList();
    updateReconstructButton();
}

function reconstructSecretAnimation() {
    if (selectedShares.length < 2) {
        alert(`Please select at least 2 shares to attempt reconstruction!`);
        return;
    }
    
    // Move selected balls towards center
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    
    shareBalls.forEach(ball => {
        if (ball.selected) {
            ball.targetX = centerX;
            ball.targetY = centerY;
            ball.targetRadius = 20;
        } else {
            ball.alpha = 0.3;
        }
    });
    
    animationState = 'reconstructing';
    animationProgress = 0;
    
    if (selectedShares.length < config.k) {
        updateStatus(`Attempting reconstruction with insufficient shares (${selectedShares.length}/${config.k})...`);
    } else if (selectedShares.length === config.k) {
        updateStatus('Reconstructing secret using minimum threshold shares...');
    } else {
        updateStatus(`Reconstructing secret using ${selectedShares.length} shares (more than needed)...`);
    }
}

function reconstructSecret() {
    try {
        if (selectedShares.length === 0) {
            throw new Error('No shares selected for reconstruction');
        }
        
        const selectedShareData = selectedShares.map(i => {
            if (i >= shares.length) {
                throw new Error('Invalid share index');
            }
            return shares[i];
        });
        
        return lagrangeInterpolation(selectedShareData);
    } catch (error) {
        console.error('Reconstruction error:', error);
        showError(`Reconstruction failed: ${error.message}`);
        return null;
    }
}

function reset() {
    animationState = 'idle';
    animationProgress = 0;
    shares = [];
    selectedShares = [];
    shareBalls = [];
    secretBall = null;
    
    document.getElementById('share-panel').style.display = 'none';
    document.getElementById('result-section').style.display = 'none';
    document.getElementById('reconstruct-btn').style.display = 'none';
    
    updateStatus('Ready to split secret...');
}

// ===========================
// UI Update Functions
// ===========================

function updateStatus(text) {
    document.getElementById('status-text').textContent = text;
}

// Enhanced error handling function
function showError(message) {
    updateStatus(message);
    
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(231, 76, 60, 0.9);
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 1000;
        font-weight: bold;
        max-width: 300px;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(toast);
    
    // Remove toast after 4 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }
    }, 4000);
}

function updateShareList() {
    const listDiv = document.getElementById('share-list');
    let html = '';
    
    shares.forEach(([x, y], index) => {
        const selected = selectedShares.includes(index);
        
        // Calculate Lagrange coefficient for this share if it's selected and we have enough shares
        let lagrangeCoeff = '';
        if (selected && selectedShares.length >= 2) {
            const coeff = calculateLagrangeCoefficient(index, selectedShares);
            lagrangeCoeff = `<div class="lagrange-coeff">L${index+1} = ${coeff.toFixed(6)}</div>`;
        }
        
        html += `
            <div class="share-item ${selected ? 'selected' : ''}" onclick="toggleShareSelection(${index})">
                <div class="share-number">Share ${index + 1}</div>
                <div class="share-data">x: ${x}<br>y: ${y}</div>
                ${lagrangeCoeff}
            </div>
        `;
    });
    
    listDiv.innerHTML = html;
    document.getElementById('required-shares').textContent = config.k;
}

function updateReconstructButton() {
    const btn = document.getElementById('reconstruct-btn');
    if (selectedShares.length >= 2) {
        btn.disabled = false;
        if (selectedShares.length >= config.k) {
            btn.textContent = `Reconstruct from ${selectedShares.length} Shares (Secure)`;
            btn.className = 'btn btn-reconstruct success';
        } else {
            btn.textContent = `Try Reconstruct with ${selectedShares.length} Shares (Insufficient!)`;
            btn.className = 'btn btn-reconstruct warning';
        }
    } else {
        btn.disabled = true;
        btn.textContent = `Select at least 2 shares to attempt reconstruction`;
        btn.className = 'btn btn-reconstruct';
    }
}

function displayResult(reconstructed, isSuccessfulReconstruction = true) {
    const resultSection = document.getElementById('result-section');
    resultSection.style.display = 'block';
    
    document.getElementById('original-value').textContent = config.secret;
    document.getElementById('reconstructed-value').textContent = reconstructed;
    
    const statusDiv = document.getElementById('result-status');
    
    if (isSuccessfulReconstruction) {
        const isMatch = Math.abs(reconstructed - config.secret) < 1;
        if (isMatch) {
            statusDiv.innerHTML = '<span class="status-icon">✅</span><span class="status-text">Perfect Match!</span>';
            statusDiv.className = 'result-status success';
        } else {
            statusDiv.innerHTML = '<span class="status-icon">❌</span><span class="status-text">Unexpected Error!</span>';
            statusDiv.className = 'result-status error';
        }
    } else {
        statusDiv.innerHTML = '<span class="status-icon">⚠️</span><span class="status-text">Insufficient Shares - Secret NOT Recovered!</span>';
        statusDiv.className = 'result-status warning';
    }
    
    // Scroll to result
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ===========================
// Event Listeners
// ===========================

document.addEventListener('DOMContentLoaded', () => {
    initCanvas();
    
    // Button events
    document.getElementById('generate-btn').addEventListener('click', splitSecret);
    document.getElementById('reconstruct-btn').addEventListener('click', reconstructSecretAnimation);
    document.getElementById('clear-btn').addEventListener('click', reset);
    
    // Enhanced input validation with immediate feedback
    const inputs = ['secret-input', 'k-input', 'n-input'];
    inputs.forEach(inputId => {
        const input = document.getElementById(inputId);
        input.addEventListener('input', validateInputsRealtime);
    });
    
    // Input validation
    const kInput = document.getElementById('k-input');
    const nInput = document.getElementById('n-input');
    
    kInput.addEventListener('change', () => {
        const k = parseInt(kInput.value);
        const n = parseInt(nInput.value);
        if (k > n) nInput.value = k;
        if (k > 8) kInput.value = 8;
        validateInputsRealtime();
    });
    
    nInput.addEventListener('change', () => {
        const k = parseInt(kInput.value);
        const n = parseInt(nInput.value);
        if (n < k) nInput.value = k;
        if (n > 8) nInput.value = 8;
        validateInputsRealtime();
    });
    
    console.log('🔐 Shamir Secret Sharing Animator initialized!');
});

function validateInputsRealtime() {
    const secret = document.getElementById('secret-input').value;
    const k = document.getElementById('k-input').value;
    const n = document.getElementById('n-input').value;
    
    const generateBtn = document.getElementById('generate-btn');
    
    if (!secret || !k || !n) {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Split Secret (Fill all fields)';
        generateBtn.style.opacity = '0.6';
        return;
    }
    
    const secretNum = parseInt(secret);
    const kNum = parseInt(k);
    const nNum = parseInt(n);
    
    if (isNaN(secretNum) || isNaN(kNum) || isNaN(nNum)) {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Split Secret (Invalid numbers)';
        generateBtn.style.opacity = '0.6';
        return;
    }
    
    if (secretNum <= 0 || kNum < 2 || nNum < 2 || kNum > nNum) {
        generateBtn.disabled = true;
        generateBtn.textContent = 'Split Secret (Check K ≤ N)';
        generateBtn.style.opacity = '0.6';
        return;
    }
    
    generateBtn.disabled = false;
    generateBtn.textContent = 'Split Secret';
    generateBtn.style.opacity = '1';
}

// Make toggleShareSelection globally accessible
window.toggleShareSelection = toggleShareSelection;
