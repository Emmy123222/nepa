export type TransactionStatus = 'idle' | 'loading' | 'success' | 'error';

export enum TransactionStep {
  IDLE = 0,
  CONNECTING = 1,
  SIGNING = 2,
  SUBMITTING = 3,
  FINALIZING = 4,
  COMPLETE = 5
}

export interface StellarState {
  address: string | null;
  status: TransactionStatus;
  currentStep: TransactionStep;
  txHash: string | null;
  error: string | null;
}

export interface PaymentFormData {
  meterNumber: string;
  amount: string;
}
