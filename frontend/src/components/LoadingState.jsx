export default function LoadingState({ message = 'Loading analysis...' }) { return <div className="loading-state"><span className="pulse" />{message}</div>; }
