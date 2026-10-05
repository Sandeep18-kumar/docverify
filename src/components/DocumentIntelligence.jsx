import { ScanText, Image, QrCode, ShieldQuestion } from "lucide-react";

function Detail({ label, value }) {
  return (
    <div className="meta-grid-row">
      <dt className="text-soft text-sm">{label}</dt>
      <dd>{value || "Not available"}</dd>
    </div>
  );
}

export default function DocumentIntelligence({ result }) {
  const metadata = result.metadata || {};
  const fields = result.extractedFields || [];
  const qrCodes = metadata.qr_codes || [];
  const visualMarks = metadata.visual_marks || {};

  return (
    <div className="card card-pad">
      <div className="row-8" style={{ marginBottom: 4 }}>
        <ScanText size={18} className="text-soft" />
        <h3 style={{ fontSize: "1.05rem" }}>Document intelligence</h3>
      </div>
      <p className="text-soft text-sm" style={{ marginBottom: 16 }}>
        Information detected from the uploaded file. Detected IDs are format-checked, not issuer-verified.
      </p>

      <div className="meta-grid">
        <Detail label="Authentication level" value={result.authenticationLevel} />
        <Detail label="OCR scan" value={metadata.ocr_used ? "Completed" : "Unavailable"} />
        <Detail label="Embedded images" value={metadata.embedded_image_count != null ? `${metadata.embedded_image_count} found` : null} />
        <Detail label="Logo / watermark" value={visualMarks.logo_or_watermark} />
      </div>

      {fields.length > 0 && (
        <div style={{ marginTop: 18 }}>
          <div className="row-8" style={{ marginBottom: 8 }}><ShieldQuestion size={16} className="text-soft" /><strong>Detected identifiers</strong></div>
          <div className="ocr-fields">
            {fields.map((field, index) => (
              <div key={`${field.field}-${index}`} className="ocr-field-row">
                <span className="text-soft text-sm">{field.field}</span>
                <span className="mono text-sm">{field.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {qrCodes.length > 0 && (
        <div style={{ marginTop: 18 }}>
          <div className="row-8" style={{ marginBottom: 8 }}><QrCode size={16} className="text-soft" /><strong>QR data</strong></div>
          {qrCodes.map((code, index) => <p key={index} className="mono text-sm" style={{ wordBreak: "break-word" }}>{code}</p>)}
        </div>
      )}

      {metadata.warnings?.length > 0 && (
        <div style={{ marginTop: 16 }}>
          {metadata.warnings.map((warning, index) => <p key={index} className="text-soft text-sm">{warning}</p>)}
        </div>
      )}
    </div>
  );
}