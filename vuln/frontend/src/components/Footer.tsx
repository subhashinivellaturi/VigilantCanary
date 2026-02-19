import React from 'react';
import { Heart, Github, Book } from 'lucide-react';
import './Footer.css';

export function Footer() {
  const year = new Date().getFullYear();

  return (
    <footer className="vc-footer">
      <div className="footer-content">
        <div className="footer-left">
          <span className="footer-text">
            Vigilant Canary v1.0.0
          </span>
          <span className="footer-sep">•</span>
          <span className="footer-text">
            Built with <Heart className="footer-icon" size={14} /> by security team
          </span>
        </div>

        <div className="footer-links">
          <a href="#docs" className="footer-link" title="Documentation">
            <Book size={14} />
            <span>Docs</span>
          </a>
          <a href="#privacy" className="footer-link" title="Privacy Policy">
            Privacy
          </a>
          <a href="#github" className="footer-link" title="GitHub Repository">
            <Github size={14} />
            <span>GitHub</span>
          </a>
        </div>

        <div className="footer-right">
          <span className="footer-text">© {year} Vigilant Canary. All rights reserved.</span>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
