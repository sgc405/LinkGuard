let isFirstScan = true;  // Track if this is the user's first scan
let safetyScore = 0;     // Track the user's safety score

// URL Scanning
async function scanURL(event) {
    event.preventDefault();
    const urlInput = document.getElementById('urlInput').value;
    const resultContent = document.getElementById('resultContent');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const scoreElement = document.getElementById('score');

    // Validate URL 
    try {
        new URL(urlInput);
    } catch (e) {
        console.error("Invalid URL:", urlInput);  // Debug
        resultContent.innerHTML = '<p class="text-danger">Error: Please enter a valid URL.</p>';
        return;
    }

    // Show loading spinner
    console.log("Starting scan for URL:", urlInput);  // Debug
    loadingSpinner.style.display = 'block';
    resultContent.innerHTML = '';

    try {
        console.log("Sending fetch request to /scan");  // Debug
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput, source: 'scan' }),
            credentials: 'same-origin'  // Include session cookies
        });
        console.log("Fetch response status:", response.status);  // Debug
        const result = await response.json();
        console.log("Fetch response data:", result);  // Debug
        if (result.error) {
            console.error("Scan error:", result.error);  // Debug
            resultContent.innerHTML = `<p class="text-danger">Error: ${result.error}</p>`;
            loadingSpinner.style.display = 'none';
            return;
        }

        const resultHtml = `
            <h3>Scan Result</h3>
            <p>URL: <a href="${result.link}" target="_blank">${result.link}</a></p>
            <p>Risk Level: <span class="risk-${result.risk_category.toLowerCase()}">${result.risk_category}</span>${result.threat_type ? ` (Threat Type: ${result.threat_type})` : ''}</p>
            <p>Details:</p>
            <ul>
                ${Object.entries(result.findings).map(([key, value]) => `<li>${key}: ${value ? "⚠️ Detected" : "✅ Safe"}</li>`).join('')}
            </ul>
            ${result.threat_report ? `<h3>Threat Report</h3><pre>${result.threat_report}</pre>` : ''}
            ${window.currentUsername ? `
            <p>Provide Feedback:</p>
            <div class="d-flex justify-content-start gap-2 mb-3">
                <button class="btn btn-outline-primary" onclick="submitFeedback('${result.link}', 'safe', '${result.risk_category}')">Mark as Safe</button>
                <button class="btn btn-outline-primary" onclick="submitFeedback('${result.link}', 'unsafe', '${result.risk_category}')">Mark as Unsafe</button>
            </div>
            ` : ''}
            
        `;
        resultContent.innerHTML = resultHtml;

        // Update Safety Score
        const grade = result.grade !== undefined ? result.grade : (result.risk_category === 'Low' ? 100 : result.risk_category === 'Medium' ? 50 : 0);
        safetyScore = grade;
        scoreElement.textContent = `${safetyScore} | ${safetyScore > 50 ? 'Good' : safetyScore === 50 ? 'Moderate' : 'Needs Improvement'}`;
        scoreElement.className = safetyScore > 50 ? 'text-success' : safetyScore === 50 ? 'text-warning' : 'text-danger';

        // Achievement for first scan
        if (isFirstScan) {
            resultContent.innerHTML += '<p class="text-success">Achievement Unlocked: First Scan!</p>';
            isFirstScan = false;
        }
    } catch (error) {
        console.error('Error scanning URL:', error);  // Debug
        resultContent.innerHTML = `<p class="text-danger">Error: ${error.message}</p>`;
    } finally {
        console.log("Hiding loading spinner");  // Debug
        loadingSpinner.style.display = 'none';
    }
}

// Chatbot with Dialogflow (proxied through Flask)
async function sendChatMessage(message) {
    if (!message) return;

    const chatMessages = document.getElementById("chatMessages");
    chatMessages.innerHTML += `<p class="user-message">You: ${message}</p>`;
    chatMessages.scrollTop = chatMessages.scrollHeight;

    try {
        const response = await fetch("/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: message })
        });
        const result = await response.json();
        if (result.error) {
            chatMessages.innerHTML += `<p class="bot-message">Chatbot: ${result.error}</p>`;
        } else {
            chatMessages.innerHTML += `<p class="bot-message">Chatbot: ${result.response}</p>`;
        }
        chatMessages.scrollTop = chatMessages.scrollHeight;
    } catch (error) {
        chatMessages.innerHTML += `<p class="bot-message">Chatbot: Error: ${error.message}</p>`;
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    document.getElementById("chatInput").value = "";
}

async function submitFeedback(url, userAssessment, originalAssessment) {
    try {
        const response = await fetch("/feedback", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url, user_assessment: userAssessment, original_assessment: originalAssessment })
        });
        const result = await response.json();
        if (result.error) {
            alert(`Error submitting feedback: ${result.error}`);
        } else {
            alert(result.message);
            // Re-scan to reflect the updated assessment
            scanURL({ preventDefault: () => {} });
        }
    } catch (error) {
        alert(`Error submitting feedback: ${error.message}`);
    }
}

// QR Code Scanning
let stream = null;

async function startQRScanner() {
    const qrScanner = document.getElementById("qrScanner");
    const qrVideo = document.getElementById("qrVideo");
    const qrCanvas = document.getElementById("qrCanvas");
    const resultContent = document.getElementById("resultContent");
    const spinner = document.getElementById("loadingSpinner");

    // Show the QR scanner
    qrScanner.classList.remove("d-none");
    const scanningMessage = document.createElement("div");
    scanningMessage.className = "scan-result";
    scanningMessage.innerHTML = "Scanning QR code... Please position the QR code in front of your camera.";
    resultContent.appendChild(scanningMessage);
    spinner.style.display = "block";

    try {
        // Access the camera
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        qrVideo.srcObject = stream;
        qrVideo.play();

        // Start scanning
        const canvasContext = qrCanvas.getContext("2d");
        const scanQR = async () => {
            if (qrVideo.readyState === qrVideo.HAVE_ENOUGH_DATA) {
                // Set canvas dimensions to match video
                qrCanvas.height = qrVideo.videoHeight;
                qrCanvas.width = qrVideo.videoWidth;

                // Draw the current video frame on the canvas
                canvasContext.drawImage(qrVideo, 0, 0, qrCanvas.width, qrCanvas.height);

                // Get image data from the canvas
                const imageData = canvasContext.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height, {
                    inversionAttempts: "dontInvert",
                });

                if (code) {
                    // QR code detected
                    const url = code.data;
                    stopQRScanner();
                    document.getElementById("urlInput").value = url;
                    try {
                        const response = await fetch("/scan", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ url: url, source: "qr_scan" })
                        });
                        const result = await response.json();
                        // Remove the scanning message
                        //resultContent.removeChild(scanningMessage);
                        resultContent.innerHTML = '';
                        if (result.error) {
                            const errorDiv = document.createElement("div");
                            errorDiv.className = "scan-result";
                            errorDiv.innerHTML = `<p class="text-danger">${result.error}</p>`;
                            resultContent.appendChild(errorDiv);
                            return;
                        }
                        const riskClass = `risk-${result.risk_category.toLowerCase()}`;
                        const resultDiv = document.createElement("div");
                        resultDiv.className = "scan-result";
                        let html = `<p>URL: ${result.link}</p>`;
                        html += `<p>Risk: <span class="${riskClass}">${result.risk_category}`;
                        if (result.threat_type) {
                            html += ` (Threat Type: ${result.threat_type.charAt(0).toUpperCase() + result.threat_type.slice(1)})`;
                        }
                        html += `</p>`;
                        html += `<p>Details:</p><ul>`;
                        for (const [check, value] of Object.entries(result.findings)) {
                            html += `<li>${check}: ${value ? "⚠️ Detected" : "✅ Safe"}</li>`;
                        }
                        html += `</ul>`;
                        console.log("User feedback for scan:", result.user_feedback);
                        if (result.user_feedback) {
                            html += `<p class="text-info">User Feedback: ${result.user_feedback}</p>`;
                        } else if (window.currentUsername) {
                            html += `
                                <div class="d-flex gap-2 mb-2">
                                    <button class="btn btn-outline-success btn-sm" onclick="submitFeedback('${result.link}', 'safe', '${result.risk_category}')">Mark as Safe</button>
                                    <button class="btn btn-outline-danger btn-sm" onclick="submitFeedback('${result.link}', 'unsafe', '${result.risk_category}')">Mark as Unsafe</button>
                                </div>
                            `;
                        }
                        if (result.threat_report) {
                            html += `<h3>Threat Report</h3>`;
                            html += `<pre>${result.threat_report}</pre>`;
                        }
                        html += `${isFirstScan ? '<p class="text-success">Achievement Unlocked: First QR Scan!</p>' : ''}`;
                        resultDiv.innerHTML = html;

                        // Update safety score for QR scan
                        const grade = result.grade !== undefined ? result.grade : (result.risk_category === 'Low' ? 100 : result.risk_category === 'Medium' ? 50 : 0);
                        safetyScore = grade;
                        document.getElementById("score").textContent = `${safetyScore} | ${safetyScore > 50 ? 'Good' : safetyScore === 50 ? 'Moderate' : 'Needs Improvement'}`;
                        document.getElementById("score").className = safetyScore > 50 ? 'text-success' : safetyScore === 50 ? 'text-warning' : 'text-danger';

                        isFirstScan = false;
                        resultContent.appendChild(resultDiv);

                        // Update score display with grade
                        document.getElementById("score").textContent = result.grade;

                        // Clear the input field
                        document.getElementById("urlInput").value = "";
                    } catch (error) {
                        // Remove the scanning message
                        resultContent.removeChild(scanningMessage);
                        const errorDiv = document.createElement("div");
                        errorDiv.className = "scan-result";
                        errorDiv.innerHTML = `<p class="text-danger">Error: ${error.message}</p>`;
                        resultContent.appendChild(errorDiv);
                    } finally {
                        spinner.style.display = "none";
                    }
                    return;
                }
            }
            requestAnimationFrame(scanQR);
        };

        requestAnimationFrame(scanQR);
    } catch (error) {
        // Remove the scanning message if it exists
        if (resultContent.contains(scanningMessage)) {
            resultContent.removeChild(scanningMessage);
        }
        const errorDiv = document.createElement("div");
        errorDiv.className = "scan-result";
        errorDiv.innerHTML = `<p class="text-danger">Error accessing camera: ${error.message}</p>`;
        resultContent.appendChild(errorDiv);
        qrScanner.classList.add("d-none");
        spinner.style.display = "none";
    }
}

function stopQRScanner() {
    const qrScanner = document.getElementById("qrScanner");
    const qrVideo = document.getElementById("qrVideo");

    // Stop the camera stream
    if (stream) {
        stream.getTracks().forEach(track => track.stop());
        stream = null;
    }
    qrVideo.srcObject = null;

    // Hide the QR scanner
    qrScanner.classList.add("d-none");
}