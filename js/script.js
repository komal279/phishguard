document.addEventListener('DOMContentLoaded', function () {
  const navToggle = document.querySelector('.mobile-toggle');
  const navLinks = document.querySelector('.nav-links');

  if (navToggle && navLinks) {
    navToggle.addEventListener('click', function () {
      navLinks.classList.toggle('open');
    });
  }

  const animatedCounters = document.querySelectorAll('[data-count]');

  const animateCounter = (element) => {
    const target = Number(element.dataset.count);
    const duration = 1600;
    const startTime = performance.now();

    const update = (now) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = Math.floor(eased * target);
      element.textContent = value + (element.dataset.suffix || '');
      if (progress < 1) requestAnimationFrame(update);
    };

    requestAnimationFrame(update);
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        if (!el.dataset.animated) {
          el.dataset.animated = 'true';
          animateCounter(el);
        }
      }
    });
  }, { threshold: 0.4 });

  animatedCounters.forEach(counter => observer.observe(counter));

  const registerForm = document.getElementById('registerForm');
  if (registerForm) {
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const meterBar = document.querySelector('.password-meter-bar');

    const evaluateStrength = (value) => {
      let score = 0;
      if (value.length >= 8) score += 1;
      if (/[A-Z]/.test(value)) score += 1;
      if (/[0-9]/.test(value)) score += 1;
      if (/[^A-Za-z0-9]/.test(value)) score += 1;

      return score;
    };

    passwordInput.addEventListener('input', () => {
      const strength = evaluateStrength(passwordInput.value);
      const width = (strength / 4) * 100;
      meterBar.style.width = width + '%';
      meterBar.style.background = strength < 2 ? 'linear-gradient(90deg, var(--red), var(--amber))' : 'linear-gradient(90deg, var(--amber), var(--green))';
    });

    registerForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const password = passwordInput.value;
      const confirmPassword = confirmPasswordInput.value;
      const notice = document.getElementById('registerNotice');

      if (password !== confirmPassword) {
        notice.className = 'notice show error';
        notice.textContent = 'Passwords do not match. Please try again.';
        return;
      }

      if (password.length < 8) {
        notice.className = 'notice show error';
        notice.textContent = 'Password must be at least 8 characters long.';
        return;
      }

      notice.className = 'notice show success';
      notice.textContent = 'Registration submitted successfully. Redirecting...';
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 1200);
    });
  }

  const urlScanForm = document.getElementById('urlScanForm');
  if (urlScanForm) {
    urlScanForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const urlInput = document.getElementById('urlInput');
      const resultBox = document.getElementById('scanResult');
      const fieldValue = (urlInput.value || '').trim();

      if (!fieldValue) {
        resultBox.className = 'scan-results visible result-malicious';
        resultBox.innerHTML = `
          <div class="result-status">
            <h3>Analysis Incomplete</h3>
            <span class="status-pill status-malicious">Error</span>
          </div>
          <p>Please enter a valid URL to continue.</p>
        `;
        return;
      }

      const suspicious = /login|verify|secure|update|bank|paypal|confirm|account|reset|claim/i.test(fieldValue);
      const hasHttps = /^https:\/\//i.test(fieldValue);
      const hasIp = /\d+\.\d+\.\d+\.\d+/.test(fieldValue);
      const lengthPenalty = fieldValue.length > 70 ? 24 : 0;
      const score = Math.min(98, 32 + (suspicious ? 32 : 0) + (!hasHttps ? 15 : 0) + (hasIp ? 18 : 0) + lengthPenalty);
      const isSafe = score < 60;

      resultBox.className = `scan-results visible ${isSafe ? 'result-safe' : 'result-malicious'}`;
      resultBox.innerHTML = `
        <div class="result-status">
          <h3>${isSafe ? 'Link is Safe' : 'Link is Malicious'}</h3>
          <span class="status-pill ${isSafe ? 'status-safe' : 'status-malicious'}">${isSafe ? 'Safe' : 'Malicious'}</span>
        </div>
        <div class="metrics-grid">
          <div class="metric-box">
            <small>Confidence Score</small>
            <strong>${Math.max(10, 100 - score)}%</strong>
          </div>
          <div class="metric-box">
            <small>Risk Score</small>
            <strong>${Math.round(score)}%</strong>
          </div>
          <div class="metric-box">
            <small>HTTPS Status</small>
            <strong>${hasHttps ? 'Enabled' : 'Disabled'}</strong>
          </div>
          <div class="metric-box">
            <small>Domain Info</small>
            <strong>${new URL(fieldValue).hostname || 'Unknown'}</strong>
          </div>
        </div>
      `;
    });
  }

  const analyzerForm = document.getElementById('analyzerForm');
  if (analyzerForm) {
    analyzerForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const input = document.getElementById('analyzerUrl');
      const result = document.getElementById('analyzerResult');
      const value = (input.value || '').trim();

      if (!value) {
        result.className = 'scan-results visible result-malicious';
        result.innerHTML = '<p>Please enter a URL before analyzing.</p>';
        return;
      }

      const hasHttps = /^https:\/\//i.test(value);
      const keywordRisk = /(verify|login|secure|bank|update|confirm|account|password)/i.test(value) ? 25 : 0;
      const ipRisk = /\d+\.\d+\.\d+\.\d+/.test(value) ? 18 : 0;
      const lengthRisk = value.length > 70 ? 18 : 0;
      const totalRisk = Math.min(96, keywordRisk + ipRisk + lengthRisk + (!hasHttps ? 12 : 0));
      const isSuspicious = totalRisk > 35;
      const isMalicious = totalRisk > 60;

      result.className = `scan-results visible ${isMalicious ? 'result-malicious' : isSuspicious ? 'result-warning' : 'result-safe'}`;
      result.innerHTML = `
        <div class="result-status">
          <h3>${isMalicious ? 'Malicious URL Detected' : isSuspicious ? 'Suspicious URL' : 'Safe URL'}</h3>
          <span class="status-pill ${isMalicious ? 'status-malicious' : 'status-safe'}">${isMalicious ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Safe'}</span>
        </div>
        <p>Confidence: <strong>${100 - totalRisk}%</strong></p>
        <p>Security Recommendations: ${isMalicious ? 'Avoid opening the link and verify via official channels.' : 'Continue with caution and review the sender details.'}</p>
      `;
    });
  }

  const emailForm = document.getElementById('emailForm');
  if (emailForm) {
    emailForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const content = document.getElementById('emailContent').value || '';
      const result = document.getElementById('emailResult');
      const suspiciousTerms = /(urgent|click here|verify|password|suspended|account|winner|immediate)/i;
      const score = suspiciousTerms.test(content) ? 82 : 28;
      const isPhishing = score >= 60;

      result.className = `scan-results visible ${isPhishing ? 'result-malicious' : 'result-safe'}`;
      result.innerHTML = `
        <div class="result-status">
          <h3>${isPhishing ? 'Phishing Email Detected' : 'Safe Email'}</h3>
          <span class="status-pill ${isPhishing ? 'status-malicious' : 'status-safe'}">${isPhishing ? 'Phishing' : 'Safe'}</span>
        </div>
        <p>Threat Score: <strong>${score}%</strong></p>
        <p>Analysis: ${isPhishing ? 'The message contains urgent language, credential requests, and suspicious wording commonly used in phishing attacks.' : 'No major indicators of phishing were found in the analyzed email content.'}</p>
      `;
    });
  }

  const contactForm = document.getElementById('contactForm');
  if (contactForm) {
    contactForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const status = document.getElementById('contactNotice');
      status.className = 'notice show success';
      status.textContent = 'Your message has been sent successfully. We will reply soon.';
      contactForm.reset();
    });
  }

  const clearButtons = document.querySelectorAll('[data-clear-target]');
  clearButtons.forEach(button => {
    button.addEventListener('click', () => {
      const target = document.getElementById(button.dataset.clearTarget);
      if (target) {
        target.value = '';
        const resultBox = document.getElementById('scanResult');
        if (resultBox) {
          resultBox.className = 'scan-results';
          resultBox.innerHTML = '';
        }
      }
    });
  });
});
