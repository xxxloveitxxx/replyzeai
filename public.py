# public.py

import os
import zipfile
import tempfile
import uuid
from io import BytesIO

from flask import Blueprint, request, send_file, jsonify, render_template, abort
from flask_cors import CORS
from docxtpl import DocxTemplate

public_bp = Blueprint("public", __name__)
# Allow CORS for demo endpoints
CORS(public_bp, resources={r"/api/*": {"origins": "*"}})

@public_bp.route("/api/generate-reply-prompt", methods=["OPTIONS", "POST"])
def generate_reply_prompt():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(force=True)
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400

    # Enhanced prompt to generate reply and three follow-ups
    enhanced_prompt = f"""
    Generate a professional reply to the following email, and then generate three follow-up emails that would be sent later.
    Format your response exactly as follows:

    === REPLY ===
    [Your main reply here]

    === FOLLOW UP 1 ===
    [First follow-up email]

    === FOLLOW UP 2 ===
    [Second follow-up email]

    === FOLLOW UP 3 ===
    [Third follow-up email]

    Email to respond to:
    {prompt}
    """

    try:
        from utils import callAIML_from_flask
        full_response = callAIML_from_flask(enhanced_prompt)
        
        # Parse the response to extract reply and follow-ups
        sections = {}
        current_section = None
        lines = full_response.split('\n')
        
        for line in lines:
            line = line.strip()
            if line == "=== REPLY ===":
                current_section = 'reply'
                sections[current_section] = []
            elif line == "=== FOLLOW UP 1 ===":
                current_section = 'follow_up_1'
                sections[current_section] = []
            elif line == "=== FOLLOW UP 2 ===":
                current_section = 'follow_up_2'
                sections[current_section] = []
            elif line == "=== FOLLOW UP 3 ===":
                current_section = 'follow_up_3'
                sections[current_section] = []
            elif current_section and line:
                sections[current_section].append(line)
        
        # Join the lines for each section
        reply = ' '.join(sections.get('reply', [])).strip()
        follow_ups = [
            ' '.join(sections.get('follow_up_1', [])).strip(),
            ' '.join(sections.get('follow_up_2', [])).strip(),
            ' '.join(sections.get('follow_up_3', [])).strip()
        ]
        
        # Remove any empty follow-ups
        follow_ups = [fu for fu in follow_ups if fu]
        
        return jsonify({
            "reply": reply,
            "follow_ups": follow_ups
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@public_bp.route("/<path:page>")
def catch_all(page):
    # don’t try to render static assets
    if page in ("signin", "favicon.ico"):
        abort(404)
    return render_template(f"{page}.html")

#--------------------------------------------------------------------------------------------------------------------------------------------------------------

@public_bp.route("/api/generate-full-kit", methods=["OPTIONS", "POST"])
def generate_full_kit():
    if request.method == "OPTIONS":
        return ("", 204)

    try:
        data = request.get_json(force=True)
        
        # Set default values for any missing fields
        defaults = {
            "transaction_type": "Purchase",
            "rent_type": "Annual Lease",
            "inspection_days": 10,
            "mortgage_years": 30,
            "interest_rate": 3.5,
            "parking_spaces": 1,
            "broker_name": "John Smith",
        }
        
        for key, value in defaults.items():
            if key not in data or not data[key]:
                data[key] = value
        
        # Generate all documents
        documents = []
        
        # LOI
        try:
            loi_tpl = DocxTemplate("templates/transaction_autopilot/loi_template.docx")
            loi_tpl.render(data)
            loi_bio = BytesIO()
            loi_tpl.save(loi_bio)
            loi_bio.seek(0)
            documents.append(("Letter_of_Intent.docx", loi_bio))
        except Exception as e:
            print(f"Error generating LOI: {e}")
        
        # PSA
        try:
            psa_tpl = DocxTemplate("templates/transaction_autopilot/psa_template.docx")
            psa_tpl.render(data)
            psa_bio = BytesIO()
            psa_tpl.save(psa_bio)
            psa_bio.seek(0)
            documents.append(("Purchase_Sale_Agreement.docx", psa_bio))
        except Exception as e:
            print(f"Error generating PSA: {e}")
        
        # Purchase Offer
        try:
            purchase_offer_tpl = DocxTemplate("templates/transaction_autopilot/purchase_offer_template.docx")
            purchase_offer_tpl.render(data)
            purchase_offer_bio = BytesIO()
            purchase_offer_tpl.save(purchase_offer_bio)
            purchase_offer_bio.seek(0)
            documents.append(("Purchase_Offer.docx", purchase_offer_bio))
        except Exception as e:
            print(f"Error generating Purchase Offer: {e}")
        
        # Agency Disclosure
        try:
            agency_tpl = DocxTemplate("templates/transaction_autopilot/agency_disclosure_template.docx")
            agency_tpl.render(data)
            agency_bio = BytesIO()
            agency_tpl.save(agency_bio)
            agency_bio.seek(0)
            documents.append(("Agency_Disclosure.docx", agency_bio))
        except Exception as e:
            print(f"Error generating Agency Disclosure: {e}")
        
        # Real Estate Purchase Agreement
        try:
            purchase_tpl = DocxTemplate("templates/transaction_autopilot/real_estate_purchase_template.docx")
            purchase_tpl.render(data)
            purchase_bio = BytesIO()
            purchase_tpl.save(purchase_bio)
            purchase_bio.seek(0)
            documents.append(("Real_Estate_Purchase_Agreement.docx", purchase_bio))
        except Exception as e:
            print(f"Error generating Real Estate Purchase Agreement: {e}")
        
        # Lease Agreement
        try:
            lease_tpl = DocxTemplate("templates/transaction_autopilot/lease_template.docx")
            lease_tpl.render(data)
            lease_bio = BytesIO()
            lease_tpl.save(lease_bio)
            lease_bio.seek(0)
            documents.append(("Lease_Agreement.docx", lease_bio))
        except Exception as e:
            print(f"Error generating Lease Agreement: {e}")
        
        # Seller Disclosure
        try:
            seller_tpl = DocxTemplate("templates/transaction_autopilot/seller_disclosure_template.docx")
            seller_tpl.render(data)
            seller_bio = BytesIO()
            seller_tpl.save(seller_bio)
            seller_bio.seek(0)
            documents.append(("Seller_Disclosure.docx", seller_bio))
        except Exception as e:
            print(f"Error generating Seller Disclosure: {e}")

        # Create a ZIP file in memory
        zip_io = BytesIO()
        with zipfile.ZipFile(zip_io, 'w') as zip_file:
            for filename, file_bio in documents:
                zip_file.writestr(filename, file_bio.getvalue())
        
        zip_io.seek(0)
        
        return send_file(
            zip_io,
            as_attachment=True,
            download_name=f"complete_closing_kit_{data.get('id', 'demo')}.zip",
            mimetype="application/zip"
        )
        
    except Exception as e:
        print(f"Error in generate_full_kit: {e}")
        return jsonify({"error": str(e)}), 500
