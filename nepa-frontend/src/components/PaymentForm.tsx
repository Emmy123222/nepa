import React, { useState } from 'react';
import { PaymentFormData } from '../types';

interface Props {
  onSubmit: (data: PaymentFormData) => void;
  isLoading: boolean;
}

export const PaymentForm: React.FC<Props> = ({ onSubmit, isLoading }) => {
  const [formData, setFormData] = useState<PaymentFormData>({ meterNumber: '', amount: '' });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Meter Number</label>
        <input 
          type="text"
          placeholder="e.g. 45012345678"
          className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition"
          value={formData.meterNumber}
          onChange={e => setFormData({ ...formData, meterNumber: e.target.value })}
          required
        />
      </div>
      <div>
        <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Amount (XLM)</label>
        <input 
          type="number"
          placeholder="0.00"
          className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none transition"
          value={formData.amount}
          onChange={e => setFormData({ ...formData, amount: e.target.value })}
          required
        />
      </div>
      <button 
        type="submit" 
        disabled={isLoading}
        className="w-full py-4 bg-blue-600 text-white rounded-2xl font-bold shadow-lg shadow-blue-200 hover:bg-blue-700 disabled:bg-blue-300 transition"
      >
        {isLoading ? 'Processing...' : 'Pay Bill Now'}
      </button>
    </form>
  );
};
