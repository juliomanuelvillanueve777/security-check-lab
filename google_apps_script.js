/**
 * ==============================================================================
 * GOOGLE APPS SCRIPT: Candidate Onboarding, Identity & Biometric Verification
 * ==============================================================================
 * 
 * Ce face acest script:
 * 1. Primește payload-ul JSON transmis de serverul Flask (serve.py).
 * 2. Creează un dosar dedicat candidatului în Google Drive (ex: "Ion Popescu (2026-10-26_22-30-00)").
 * 3. Decodifică toate fișierele Base64 primite (documente identitate, proof of address,
 *    captura foto și înregistrarea video biometrică WebM) și le salvează în Google Drive.
 * 4. Configurează permisiunile fișierelor astfel încât să poată fi vizualizate direct prin link.
 * 5. Inserează toate datele candidatului și link-urile directe Google Drive în Google Sheets.
 * 6. Creează automat antetele (headers) formatate dacă foaia de calcul este nouă/goală.
 *
 * INSTRUCȚIUNI DE CONFIGURARE:
 * 1. Accesați https://script.google.com sau deschideți un Google Sheet și alegeți Extensions > Apps Script.
 * 2. Înlocuiți codul din Code.gs cu acest fișier.
 * 3. (Opțional) Completați SPREADSHEET_ID sau FOLDER_ID dacă doriți foldere existente. Dacă le lăsați goale,
 *    scriptul va crea automat un folder și un sheet dedicat în Google Drive!
 * 4. Faceți click pe "Deploy" > "New deployment".
 * 5. Alegeți tipul: "Web app".
 * 6. La "Execute as", selectați: "Me (<email-ul dvs.>)".
 * 7. La "Who has access", selectați: "Anyone" (FOARTE IMPORTANT pentru a permite primirea datelor de la Flask).
 * 8. Click pe "Deploy", autorizați permisiunile Google când vi se cere.
 * 9. Copiați URL-ul Web App generat (ex: https://script.google.com/macros/s/.../exec).
 * 10. Setați variabila de mediu în server sau în hosting (Render):
 *     GOOGLE_APPS_SCRIPT_URL = <URL-ul Web App>
 * ==============================================================================
 */

// CONFIGURARE OPȚIONALĂ (Lăsați "" pentru generare automată)
var CONFIG = {
  // ID-ul folderului părinte din Google Drive unde se vor crea dosarele candidaților.
  // Dacă este gol, scriptul va crea automat folderul "Candidate Submissions - Security Check Lab"
  FOLDER_ID: "",

  // ID-ul Google Sheet unde se salvează datele candidaților.
  // Dacă este gol și rulați din Google Sheet, se folosește foaia activă; dacă e standalone, creează automat un Google Sheet.
  SPREADSHEET_ID: "",

  // Numele tab-ului din Google Sheet
  SHEET_NAME: "Candidates"
};

/**
 * Endpoint GET - Verificare status Web App
 */
function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "online",
    message: "Google Apps Script Web App for Security Check Lab is active and ready to receive POST submissions.",
    timestamp: new Date().toISOString()
  })).setMimeType(ContentService.MimeType.JSON);
}

/**
 * Endpoint POST - Recepționare aplicație candidat, salvare în Drive & Sheets
 */
function doPost(e) {
  var lock = LockService.getScriptLock();
  try {
    // Așteptăm până la 30 secunde pentru a preveni coliziunile simultane la scrierea în Google Sheet
    lock.waitLock(30000);

    var rawContents = (e && e.postData && e.postData.contents) ? e.postData.contents : null;
    if (!rawContents) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "No POST body contents received"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    var payload = JSON.parse(rawContents);
    var formData = payload.formData || {};
    var files = payload.files || [];
    var candidateName = payload.candidateName || (formData.firstName + " " + formData.lastName) || "Candidate_Unknown";
    var submittedAt = payload.submittedAt || new Date().toISOString();

    // 1. Obținere sau creare folder principal în Google Drive
    var mainFolder = getMainFolder();

    // 2. Creare folder dedicat pentru candidatul curent
    var timeFormatted = Utilities.formatDate(new Date(), Session.getScriptTimeZone() || "GMT", "yyyy-MM-dd_HH-mm-ss");
    var candidateFolder = mainFolder.createFolder(candidateName + " (" + timeFormatted + ")");
    var candidateFolderUrl = candidateFolder.getUrl();

    // 3. Salvare fișiere în folderul candidatului
    var fileUrls = {
      docFile: "",
      poaFile: "",
      rtwFile: "",
      cvFile: "",
      facialCapture: "",
      videoVerification: ""
    };

    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      if (!f || !f.data) continue;

      try {
        var decodedBytes = Utilities.base64Decode(f.data);
        var mime = f.mimeType || "application/octet-stream";
        var fileName = f.filename || ("file_" + (i + 1));
        var blob = Utilities.newBlob(decodedBytes, mime, fileName);
        var driveFile = candidateFolder.createFile(blob);

        // Permite vizualizarea fișierului prin link
        try {
          driveFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
        } catch (shareErr) {
          Logger.log("Sharing permission warning: " + shareErr);
        }

        var directUrl = driveFile.getUrl();
        if (f.field) {
          fileUrls[f.field] = directUrl;
        }
      } catch (fileErr) {
        Logger.log("Eroare la salvarea fișierului " + f.filename + ": " + fileErr);
      }
    }

    // 4. Obținere foaie de calcul Google Sheets
    var sheet = getCandidateSheet();

    // 5. Verificare și adăugare Header dacă foaia este nouă/goală
    ensureHeaders(sheet);

    // 6. Construire rând cu datele candidatului
    var rowData = [
      submittedAt,
      formData.fullName || candidateName,
      formData.firstName || "",
      formData.lastName || "",
      formData.email || "",
      formData.phone || "",
      formData.dob || "",
      formData.address || "",
      formData.city || "",
      formData.postcode || "",
      formData.rtw || "",
      formData.nino || "",
      formData.employer || "",
      formData.jobTitle || "",
      formData.salary || "",
      formData.duration || "",
      formData.livedFiveYears || "",
      formData.currentAddressHistory || "",
      formData.previousAddressHistory || "",
      formData.docType || "",
      formData.poaDocType || "",
      formData.dbsConsent || "Consented",
      formData.declarationSignature || "",
      candidateFolderUrl,
      fileUrls.docFile || "",
      fileUrls.poaFile || "",
      fileUrls.rtwFile || "",
      fileUrls.cvFile || "",
      fileUrls.facialCapture || "",
      fileUrls.videoVerification || ""
    ];

    // Adăugare date în Google Sheet
    sheet.appendRow(rowData);

    return ContentService.createTextOutput(JSON.stringify({
      status: "success",
      message: "Candidatul și fișierele au fost salvate cu succes în Google Sheets și Google Drive!",
      candidateFolder: candidateFolderUrl,
      files: fileUrls
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    Logger.log("Eroare în doPost: " + err.toString());
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Găsește sau creează folderul părinte în Google Drive
 */
function getMainFolder() {
  if (CONFIG.FOLDER_ID && CONFIG.FOLDER_ID.trim() !== "") {
    try {
      return DriveApp.getFolderById(CONFIG.FOLDER_ID.trim());
    } catch (e) {
      Logger.log("Folderul specificat prin FOLDER_ID nu a putut fi accesat: " + e);
    }
  }

  var folderName = "Candidate Submissions - Security Check Lab";
  var folders = DriveApp.getFoldersByName(folderName);
  if (folders.hasNext()) {
    return folders.next();
  }
  return DriveApp.createFolder(folderName);
}

/**
 * Găsește sau creează Google Sheet-ul pentru salvarea datelor
 */
function getCandidateSheet() {
  var ss = null;

  if (CONFIG.SPREADSHEET_ID && CONFIG.SPREADSHEET_ID.trim() !== "") {
    try {
      ss = SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID.trim());
    } catch (e) {
      Logger.log("Spreadsheet-ul specificat prin SPREADSHEET_ID nu a putut fi deschis: " + e);
    }
  }

  // Dacă nu e specificat ID, verificăm dacă scriptul este atașat unui Google Sheet
  if (!ss) {
    try {
      ss = SpreadsheetApp.getActiveSpreadsheet();
    } catch (e) {}
  }

  // Dacă încă nu există, căutăm după nume sau creăm unul nou în Google Drive
  if (!ss) {
    var sheetName = "Candidate Applications - DBS & Identity Check";
    var files = DriveApp.getFilesByName(sheetName);
    if (files.hasNext()) {
      ss = SpreadsheetApp.open(files.next());
    } else {
      ss = SpreadsheetApp.create(sheetName);
      var mainFolder = getMainFolder();
      var driveFile = DriveApp.getFileById(ss.getId());
      mainFolder.addFile(driveFile);
      DriveApp.getRootFolder().removeFile(driveFile);
    }
  }

  var sheet = ss.getSheetByName(CONFIG.SHEET_NAME);
  if (!sheet) {
    sheet = ss.getSheets()[0];
    try {
      sheet.setName(CONFIG.SHEET_NAME);
    } catch (e) {}
  }
  return sheet;
}

/**
 * Verifică dacă foaia are antete; dacă e goală, creează coloanele și le formatează
 */
function ensureHeaders(sheet) {
  if (sheet.getLastRow() === 0) {
    var headers = [
      "Submission Timestamp",
      "Full Name",
      "First Name",
      "Last Name",
      "Email Address",
      "Phone Number",
      "Date of Birth",
      "Current Address",
      "City",
      "Postcode",
      "RTW Share Code / Status",
      "National Insurance (NINO)",
      "Current / Previous Employer",
      "Job Title",
      "Salary",
      "Employment Duration",
      "Lived 5 Years at Address",
      "Current Address History",
      "Previous Address History (5 Years)",
      "Identity Document Type",
      "Proof of Address Document Type",
      "DBS Consent",
      "Declaration Signature",
      "Candidate Folder (Google Drive)",
      "Identity Document (Google Drive Link)",
      "Proof of Address Document (Google Drive Link)",
      "Right to Work Document (Google Drive Link)",
      "CV / Resume Document (Google Drive Link)",
      "Facial Photo Still (Google Drive Link)",
      "Facial Video Verification (Google Drive Link)"
    ];

    sheet.appendRow(headers);

    // Formatare profesională a antetului
    var headerRange = sheet.getRange(1, 1, 1, headers.length);
    headerRange.setFontWeight("bold");
    headerRange.setBackground("#1e293b"); // Gri închis modern (slate-800)
    headerRange.setFontColor("#ffffff");
    headerRange.setHorizontalAlignment("center");
    headerRange.setVerticalAlignment("middle");
    sheet.setRowHeight(1, 36);
    sheet.setFrozenRows(1);

    // Auto-ajustare lățime pentru primele coloane
    for (var col = 1; col <= headers.length; col++) {
      sheet.autoResizeColumn(col);
    }
  }
}
