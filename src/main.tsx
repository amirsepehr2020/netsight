import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import SettingsPanel from './SettingsPanel';
import './styles.css';
import './device-fixes.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <>
      <App />
      <SettingsPanel />
    </>
  </StrictMode>,
);
