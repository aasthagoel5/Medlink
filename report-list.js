// Function to get the file category from the current URL path
function getCategoryFromPath() {
    // 1. Get the current page filename (e.g., "xray_files.html")
    const path = window.location.pathname;
    const filename = path.substring(path.lastIndexOf('/') + 1);

    // 2. Remove the '.html' extension and replace '_' with '-' (e.g., "xray_files" -> "xray-files")
    let baseName = filename.replace(/\.html$/, '').replace(/_/g, '-');

    // 3. For the main index page (assuming it's named 'index.html'), we don't fetch a list.
    if (baseName === 'index') return null; 

    // 4. Return the clean, lowercase category slug (e.g., "xray-files")
    return baseName; 
}

// Function to fetch and render reports
async function fetchAndRenderReportsList() {
    const token = localStorage.getItem('medlink_token'); // Ensure this matches your Login script's key
    const categorySlug = getCategoryFromPath(); 

    // If we are on the main index page, stop here (it doesn't have a report list container)
    if (!categorySlug) return; 

    // Convert slug back to readable title for display (e.g., "xray-files" -> "Xray Files")
    const displayCategory = categorySlug
        .split('-')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' '); 

    const listContainer = document.querySelector('.main-content'); // Use a container present in all pages

    if (!token) {
        listContainer.innerHTML = `<div class="empty-state">
            <i class="fas fa-lock"></i>
            <p>Please log in to view your files.</p>
        </div>`;
        return;
    }

    // Replace empty state with loading message while fetching
    listContainer.innerHTML = `<h2 style="text-align: center; margin-top: 50px;">Loading ${displayCategory} reports...</h2>`;

    try {
        // CORRECTED API CALL: Use the backend's required structure: /api/reports/list/:category
        const response = await fetch(`http://localhost:3000/api/reports/list/${categorySlug}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            // Check for specific 404/no data errors
            if (response.status === 404 || (result.data && result.data.length === 0)) {
                // Restore the empty state div for pages with no data
                listContainer.innerHTML = `<div class="empty-state">
                    <i class="fas fa-folder-open"></i>
                    <p>No ${displayCategory} stored yet.</p>
                    <p style="font-size: 14px; color: #999;">Tap the upload icon to add your first report.</p>
                </div>`;
                return;
            }
            throw new Error(`API Error: ${result.message || response.statusText}`);
        }
        
        const reports = result.data;
        
        let listHTML = `<h1 class="page-title" style="margin-left: 40px;">${displayCategory}</h1><ul class="report-list" style="padding: 0 40px;">`;
        
        reports.forEach(report => {
            // Assuming your backend filename column holds the user-friendly name, and size is in bytes
            const reportDate = new Date(report.upload_date).toLocaleDateString();
            const filesizeMB = (report.size / (1024 * 1024)).toFixed(2); // Convert to MB
            
            listHTML += `
            <li class="report-item" style="border-bottom: 1px solid #eee; padding: 15px 0;">
                <p class="file-name" style="font-weight: 600; color: #333;">${report.filename}</p>
                <div class="report-details" style="display: flex; justify-content: space-between; font-size: 14px; color: #666;">
                    <p>Date: ${reportDate}</p>
                    <p>Size: ${filesizeMB} MB</p>
                </div>
                <a href="http://localhost:3000/api/download/${report.id}" target="_blank" class="download-link" style="color: #8A2BE2; text-decoration: none; display: block; margin-top: 5px;">
                    <i class="fas fa-download"></i> Download
                </a>
            </li>`;
        });
        
        listHTML += '</ul>';
        // Note: You might need to update the HTML structure of your report list pages to handle this new output inside .main-content
        listContainer.innerHTML = listHTML;

    } catch (error) {
        console.error('Error fetching reports:', error);
        listContainer.innerHTML = `<div class="empty-state" style="margin-top: 50px;">
            <i class="fas fa-exclamation-circle" style="color: red;"></i>
            <p>Error loading reports. Please check your server and token.</p>
        </div>`;
    }
}
document.addEventListener('DOMContentLoaded', fetchAndRenderReportsList);