import React from 'react';
import { useStellar } from './hooks/useStellar';
import { WalletConnector } from './components/WalletConnector';
import { PaymentForm } from './components/PaymentForm';
import { ProgressStepper } from './components/ProgressStepper';
import { Loading } from './components/Loading';

const App: React.FC = () => {
  const { address, status, currentStep, txHash, error, connectWallet, sendPayment, reset } = useStellar();

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col items-center py-12 px-4">
      <div className="w-full max-w-md space-y-6">
        <header className="flex justify-between items-center">
          <h1 className="text-2xl font-black text-blue-600">NEPA</h1>
          <WalletConnector address={address} onConnect={connectWallet} />
        </header>

        <main className="bg-white rounded-3xl shadow-xl border border-slate-200 p-6">
            {status === 'loading' ? (
              <div className="py-8 space-y-6">
                <Loading label={currentStep === 1 ? "Connecting..." : "Processing Transaction..."} />
                <ProgressStepper currentStep={currentStep} />
              </div>
            ) : status === 'success' ? (
              <div className="py-8 text-center space-y-4">
                <div className="w-16 h-16 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto text-2xl">✓</div>
                <h3 className="text-lg font-bold">Success!</h3>
                <code className="text-[10px] text-blue-600 block bg-slate-50 p-2 rounded">{txHash}</code>
                <button onClick={reset} className="w-full py-3 bg-blue-600 text-white rounded-xl font-bold">New Payment</button>
              </div>
            ) : (
              <PaymentForm onSubmit={sendPayment} isLoading={false} />
            )}
            {error && <div className="mt-4 p-3 bg-red-50 text-red-600 text-xs rounded-lg">{error}</div>}
        </main>
      </div>
    </div>
  );
};

export default App;
