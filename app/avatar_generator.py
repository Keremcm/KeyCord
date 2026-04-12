"""
Local Avatar Generator - Replaces ui-avatars.com dependency
Generates SVG avatars with initials and random background colors
"""
import hashlib
from flask import Response

def generate_avatar_svg(name, size=128):
    """
    Generate an SVG avatar with initials from the name
    
    Args:
        name: User's name or username
        size: Size of the avatar (default 128px)
    
    Returns:
        SVG string
    """
    # Get initials (first letter of first two words)
    words = name.strip().upper().split()
    if len(words) >= 2:
        initials = words[0][0] + words[1][0]
    elif len(words) == 1 and len(words[0]) >= 2:
        initials = words[0][0:2]
    elif len(words) == 1:
        initials = words[0][0]
    else:
        initials = "?"
    
    # Generate consistent color from name hash
    name_hash = hashlib.md5(name.encode()).hexdigest()
    hue = int(name_hash[:2], 16) * 360 / 255
    
    # Use HSL for better color variety
    # Keeping saturation and lightness moderate for readability
    background_color = f"hsl({hue:.0f}, 65%, 55%)"
    text_color = "#ffffff"
    
    # Generate SVG
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">
    <rect width="{size}" height="{size}" fill="{background_color}"/>
    <text x="50%" y="50%" text-anchor="middle" dy=".35em" fill="{text_color}" font-family="Arial, sans-serif" font-size="{size//2}" font-weight="bold">{initials}</text>
</svg>'''
    
    return svg

def avatar_response(name, size=128):
    """
    Create a Flask Response object with SVG avatar
    
    Args:
        name: User's name or username
        size: Size of the avatar
    
    Returns:
        Flask Response with SVG content
    """
    svg = generate_avatar_svg(name, size)
    return Response(svg, mimetype='image/svg+xml')
