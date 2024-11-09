// src/components/ui/alert.tsx
import React from 'react';
import { Alert as MuiAlert, AlertTitle } from '@mui/material';

interface AlertProps {
  children: React.ReactNode;
  className?: string;
}

export const Alert: React.FC<AlertProps> = ({ children, className }) => {
  return (
    <MuiAlert severity="info" className={className}>
      {children}
    </MuiAlert>
  );
};

export const AlertDescription: React.FC = ({ children }) => {
  return <span>{children}</span>;
};
