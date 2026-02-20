import { useState } from 'react';
import { StellarState, PaymentFormData, TransactionStep } from '../types';

export const useStellar = () => {
  const [state, setState] = useState<StellarState>({
    address: null,
    status: 'idle',
    currentStep: TransactionStep.IDLE,
    txHash: null,
    error: null,
  });

  const connectWallet = async () => {
    setState(prev => ({ ...prev, status: 'loading', currentStep: TransactionStep.CONNECTING }));
    setTimeout(() => {
      setState({ address: "G...NEPA", status: 'idle', currentStep: TransactionStep.IDLE, txHash: null, error: null });
    }, 1500);
  };

  const sendPayment = async (data: PaymentFormData) => {
    console.log("Paying for meter:", data.meterNumber);
    setState(prev => ({ ...prev, status: 'loading', currentStep: TransactionStep.SIGNING }));

    setTimeout(() => {
      setState(prev => ({ ...prev, currentStep: TransactionStep.SUBMITTING }));
      setTimeout(() => {
        setState(prev => ({ ...prev, currentStep: TransactionStep.FINALIZING }));
        setTimeout(() => {
          setState({ ...state, status: 'success', currentStep: TransactionStep.COMPLETE, txHash: "7b4c...f2e1", error: null });
        }, 2000);
      }, 2000);
    }, 1500);
  };

  const reset = () => setState(prev => ({ ...prev, status: 'idle', currentStep: TransactionStep.IDLE }));

  return { ...state, connectWallet, sendPayment, reset };
};
