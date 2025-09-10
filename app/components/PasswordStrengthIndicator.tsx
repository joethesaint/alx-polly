'use client';

import { useState, useEffect } from 'react';
import { Check, X } from 'lucide-react';

interface PasswordStrengthIndicatorProps {
  password: string;
  className?: string;
}

interface PasswordRequirement {
  label: string;
  test: (password: string) => boolean;
  met: boolean;
}

export function PasswordStrengthIndicator({ password, className = '' }: PasswordStrengthIndicatorProps) {
  const [requirements, setRequirements] = useState<PasswordRequirement[]>([
    {
      label: 'At least 8 characters',
      test: (pwd) => pwd.length >= 8,
      met: false
    },
    {
      label: 'One uppercase letter',
      test: (pwd) => /[A-Z]/.test(pwd),
      met: false
    },
    {
      label: 'One lowercase letter',
      test: (pwd) => /[a-z]/.test(pwd),
      met: false
    },
    {
      label: 'One number',
      test: (pwd) => /[0-9]/.test(pwd),
      met: false
    },
    {
      label: 'One special character',
      test: (pwd) => /[^A-Za-z0-9]/.test(pwd),
      met: false
    }
  ]);

  useEffect(() => {
    setRequirements(prev => 
      prev.map(req => ({
        ...req,
        met: req.test(password)
      }))
    );
  }, [password]);

  const metCount = requirements.filter(req => req.met).length;
  const strength = metCount === 0 ? 'weak' : metCount <= 2 ? 'weak' : metCount <= 4 ? 'medium' : 'strong';
  
  const getStrengthColor = () => {
    switch (strength) {
      case 'weak': return 'bg-red-500';
      case 'medium': return 'bg-yellow-500';
      case 'strong': return 'bg-green-500';
      default: return 'bg-gray-300';
    }
  };

  const getStrengthText = () => {
    switch (strength) {
      case 'weak': return 'Weak';
      case 'medium': return 'Medium';
      case 'strong': return 'Strong';
      default: return 'Very Weak';
    }
  };

  if (!password) return null;

  return (
    <div className={`space-y-3 ${className}`}>
      {/* Strength Bar */}
      <div className="space-y-1">
        <div className="flex justify-between text-sm">
          <span className="text-slate-600">Password Strength</span>
          <span className={`font-medium ${
            strength === 'weak' ? 'text-red-600' : 
            strength === 'medium' ? 'text-yellow-600' : 
            'text-green-600'
          }`}>
            {getStrengthText()}
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div 
            className={`h-2 rounded-full transition-all duration-300 ${getStrengthColor()}`}
            style={{ width: `${(metCount / requirements.length) * 100}%` }}
          />
        </div>
      </div>

      {/* Requirements List */}
      <div className="space-y-1">
        <p className="text-sm font-medium text-slate-700">Password Requirements:</p>
        <ul className="space-y-1">
          {requirements.map((req, index) => (
            <li key={index} className="flex items-center gap-2 text-sm">
              {req.met ? (
                <Check className="w-4 h-4 text-green-600" />
              ) : (
                <X className="w-4 h-4 text-red-500" />
              )}
              <span className={req.met ? 'text-green-700' : 'text-slate-600'}>
                {req.label}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default PasswordStrengthIndicator;