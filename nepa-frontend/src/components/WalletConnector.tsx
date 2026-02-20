import React from 'react';

interface Props {
  address: string | null;
  onConnect: () => void;
}

export const WalletConnector: React.FC<Props> = ({ address, onConnect }) => {
  return (
    <div className="flex items-center gap-4">
      {address ? (
        <span className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-xs font-medium">
          Connected: {address.slice(0, 4)}...{address.slice(-4)}
        </span>
      ) : (
        <button 
          onClick={onConnect}
          className="px-4 py-2 bg-blue-600 text-white rounded-xl text-xs font-bold hover:bg-blue-700 transition"
        >
          Connect Wallet
        </button>
      )}
    </div>
  );
};
