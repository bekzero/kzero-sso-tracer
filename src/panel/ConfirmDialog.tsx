interface ConfirmDialogProps {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

const ConfirmDialog = ({
  title,
  message,
  confirmLabel = "Export",
  cancelLabel = "Cancel",
  onConfirm,
  onCancel
}: ConfirmDialogProps): JSX.Element => (
  <div className="modal-overlay" onClick={e => { if (e.target === e.currentTarget) onCancel(); }}>
    <div className="confirm-dialog">
      <h2>{title}</h2>
      <p>{message}</p>
      <div className="confirm-actions">
        <button className="btn btn-ghost" onClick={onCancel}>{cancelLabel}</button>
        <button className="btn btn-primary" onClick={onConfirm}>{confirmLabel}</button>
      </div>
    </div>
  </div>
);

export default ConfirmDialog;
