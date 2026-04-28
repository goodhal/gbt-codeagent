export class SimpleCharts {
  pieChart(containerId, data) {
    const container = document.querySelector(containerId);
    if (!container) return;

    const total = data.reduce((sum, item) => sum + item.value, 0);
    if (total === 0) return;

    let currentAngle = 0;
    const size = Math.min(container.clientWidth, container.clientHeight) || 200;
    const radius = (size - 40) / 2;

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '100%');

    const centerX = size / 2;
    const centerY = size / 2;

    data.forEach((item, index) => {
      const angle = (item.value / total * 360);
      const startAngle = currentAngle;
      const endAngle = currentAngle + angle;

      const startRad = (startAngle - 90) * Math.PI / 180;
      const endRad = (endAngle - 90) * Math.PI / 180;

      const x1 = centerX + radius * Math.cos(startRad);
      const y1 = centerY + radius * Math.sin(startRad);
      const x2 = centerX + radius * Math.cos(endRad);
      const y2 = centerY + radius * Math.sin(endRad);

      const largeArcFlag = angle > 180 ? 1 : 0;

      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      const d = [
        'M ' + centerX + ', ' + centerY,
        'L ' + x1 + ', ' + y1,
        'A ' + radius + ', ' + radius + ', 0, ' + largeArcFlag + ', 1, ' + x2 + ', ' + y2,
        'Z'
      ].join(' ');

      path.setAttribute('d', d);
      path.setAttribute('fill', item.color || this.getColor(index));
      path.setAttribute('style', 'cursor: pointer; transition: opacity 0.2s;');

      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      const percentage = ((item.value / total) * 100).toFixed(1);
      title.textContent = item.label + ': ' + item.value + ' (' + percentage + '%)';
      path.appendChild(title);

      svg.appendChild(path);
      currentAngle = endAngle;
    });

    container.innerHTML = '';
    container.appendChild(svg);
  }

  barChart(containerId, data) {
    const container = document.querySelector(containerId);
    if (!container) return;

    const maxValue = Math.max(...data.map(item => item.value), 1);
    const width = Math.max(container.clientWidth, 400);
    const height = 200;

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', height);

    const barWidth = (width - 60) / data.length - 10;
    const padding = 30;

    data.forEach((item, index) => {
      const barHeight = (item.value / maxValue) * (height - 40);
      const x = padding + index * ((width - 60) / data.length) + 5;
      const y = height - 10 - barHeight;

      const bar = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      bar.setAttribute('x', x);
      bar.setAttribute('y', y);
      bar.setAttribute('width', barWidth);
      bar.setAttribute('height', barHeight);
      bar.setAttribute('fill', item.color || this.getColor(index));
      bar.setAttribute('rx', '4');
      svg.appendChild(bar);

      const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      label.setAttribute('x', x + barWidth / 2);
      label.setAttribute('y', height - 5);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('font-size', '10');
      label.setAttribute('fill', '#666');
      label.textContent = item.label.length > 6 ? item.label.substring(0, 6) + '..' : item.label;
      svg.appendChild(label);

      const value = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      value.setAttribute('x', x + barWidth / 2);
      value.setAttribute('y', y - 5);
      value.setAttribute('text-anchor', 'middle');
      value.setAttribute('font-size', '12');
      value.setAttribute('font-weight', 'bold');
      value.textContent = item.value;
      svg.appendChild(value);
    });

    container.innerHTML = '';
    container.appendChild(svg);
  }

  getColor(index) {
    const colors = [
      '#ef4444', '#f97316', '#f59e0b', '#10b981',
      '#3b82f6', '#8b5cf6', '#06b6d4', '#14b8a6'
    ];
    return colors[index % colors.length];
  }
}