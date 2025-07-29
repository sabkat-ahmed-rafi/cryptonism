<style>
.hero-title {
  font-size: clamp(3rem, 10vw, 8rem) !important; /* responsive font size */
  font-weight: 900 !important;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
  color: #1080f0 !important;
  text-align: center;
  margin: 0;
  letter-spacing: -1px;
  line-height: 1.5;
  position: relative !important;
  z-index: 1;
  animation: fadeSlideIn 1.2s ease-out forwards !important;
  background: linear-gradient(135deg, #1080f0, #131314ff) !important;
  background-clip: text !important;
  -webkit-background-clip: text !important;
  color: transparent !important;
}

/* Underline effect using pseudo-element */
.hero-title::after {
  content: '';
  display: block;
  width: 60%;
  height: 4px;
  margin: 0.5rem auto 0;
  background: linear-gradient(90deg, #1080f0, #131314ff);
  border-radius: 4px;
  animation: underlineExpand 1s ease-out 0.8s forwards;
  transform: scaleX(0);
  transform-origin: center;
}

/* Entry animation */
@keyframes fadeSlideIn {
  from {
    opacity: 0;
    transform: translateY(-40px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Underline animation */
@keyframes underlineExpand {
  to {
    transform: scaleX(1);
  }
}


/* Hero Description - animated gradient text glow */
.hero-description {
  font-size: 1.8rem !important;
  font-weight: 700 !important;
  font-family: 'Fira Code', monospace !important;
  text-align: center !important;
  margin: 30px auto 20px !important;
  max-width: 800px !important;
  background: linear-gradient(135deg, #00c9ff, #131314ff) !important;
  background-clip: text !important;
  -webkit-background-clip: text !important;
  color: transparent !important;
  animation: gradientMove 4s linear infinite !important;
}

/* Cool Hero Tags - glass style with hover pop and glowing border */
.hero-tags {
  display: flex !important;
  flex-wrap: wrap !important;
  justify-content: center !important;
  gap: 14px !important;
  margin-top: 40px !important;
  padding: 0 16px !important;
}

.hero-tags p {
  padding: 10px 20px !important;
  border-radius: 20px !important;
  background: rgba(0, 81, 254, 0.05) !important;
  border: 1px solid rgba(0, 81, 255, 0.1) !important;
  color: #131314ff !important;
  font-family: 'Fira Code', monospace !important;
  font-size: 0.95rem !important;
  font-weight: 600 !important;
  backdrop-filter: blur(6px) !important;
  box-shadow: 0 0 8px rgba(0, 128, 255, 0.1) !important;
  transition: all 0.3s ease-in-out !important;
  cursor: default !important;
}

.hero-tags p:hover {
  transform: scale(1.07);
  box-shadow: 0 0 12px rgba(0, 128, 255, 0.6);
  border-color: rgba(0, 128, 255, 0.4);
}

/* Gradient animation */
@keyframes gradientMove {
  0% {
    background-position: 0%;
  }
  100% {
    background-position: 200%;
  }
}


  /* Smaller screens */
  @media (max-width: 768px) {
    .hero-title {
      font-size: 45px !important;
      font-weight: 900 !important;
    }

    .hero-description {
      font-size: 16px;
      padding: 0 20px;
    }

    .hero-tags {
      display: none !important;
    }
  }
</style>


<h1 class="hero-title">Cryptonism</h1>

<p class="hero-description">A frontend end-to-end encryption library for browser to secure authentication and sensitive data with zero-knowledge architecture</p>


<div class="hero-tags">
   <p>Secure</p>
   <p>Robust</p>
   <p>Flexible</p>
   <p>Modern</p>
   <p>Production Ready</p>
</div>

[Get Started](#quick-start)
[View Functions](/functions/)

![color](#f0f0f0)