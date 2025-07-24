let chart;

    function initChart() {
      const ctx = document.getElementById('chart').getContext('2d');
      chart = new Chart(ctx, {
        type: 'pie',
        data: {
          labels: [],
          datasets: [{
            data: [],
            backgroundColor: [
              '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd',
              '#8c564b', '#e377c2', '#7f7f7f'
            ],
            borderColor: '#0a192f',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            datalabels: {
              color: '#e6f1ff',
              font: {
                size: 15,
                weight: 'bold'
              },
              formatter: (value, context) => {
                const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return percentage >= 5 ? `${percentage}%` : '';
              },
              display: (context) => {
                const active = context.active;
                if (active) return true;

                const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                const percentage = ((context.dataset.data[context.dataIndex] / total) * 100).toFixed(1);
                return percentage >= 5;
              }
            },
            legend: {
              display: false
            },
            tooltip: {
              callbacks: {
                label: function(context) {
                  const label = context.label || '';
                  const value = context.raw || 0;
                  const total = context.dataset.data.reduce((a, b) => a + b, 0);
                  const percentage = ((value / total) * 100).toFixed(1);
                  return `${label}: ${value} (${percentage}%)`;
                }
              }
            }
          },
          onHover: (event, chartElements) => {
            if (chartElements && chartElements.length) {
              chart.update();
            }
          }
        },
        plugins: [ChartDataLabels]
      });
    }

    function updateLegend(labels, colors) {
      const legendContainer = document.getElementById('chart-legend');
      legendContainer.innerHTML = '';

      labels.forEach((label, index) => {
        const legendItem = document.createElement('div');
        legendItem.className = 'legend-item';

        const colorBox = document.createElement('div');
        colorBox.className = 'legend-color';
        colorBox.style.backgroundColor = colors[index];

        const labelText = document.createElement('span');
        labelText.textContent = label;

        legendItem.appendChild(colorBox);
        legendItem.appendChild(labelText);
        legendContainer.appendChild(legendItem);
      });
    }

    function updateChart() {
      fetch('/get_chart_data')
        .then(response => response.json())
        .then(data => {
          chart.data.labels = data.labels;
          chart.data.datasets[0].data = data.values;
          chart.update();
          updateLegend(data.labels, chart.data.datasets[0].backgroundColor);
        });
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
      });
      document.querySelectorAll('.tab').forEach(btn => {
        btn.classList.remove('active');
      });

      document.getElementById(tabId).classList.add('active');
      document.querySelector(`.tab[onclick="switchTab('${tabId}')"]`).classList.add('active');
    }

    function createRepoInfoElement(repoInfo) {
      const container = document.createElement('div');
      container.className = 'repo-info';

      const html = `
        <div class="repo-info-item">
          <span class="repo-info-label">Описание:</span>
          <span>${repoInfo.description || 'Отсутствует'}</span>
        </div>
        <div class="repo-info-item">
          <span class="repo-info-label">Язык:</span>
          <span>${repoInfo.language || 'Не указан'}</span>
        </div>
        <div class="repo-info-item">
          <span class="repo-info-label">Звёзды:</span>
          <span>${repoInfo.stars || 0}</span>
        </div>
        <div class="repo-info-item">
          <span class="repo-info-label">Форки:</span>
          <span>${repoInfo.forks || 0}</span>
        </div>
      `;

      container.innerHTML = html;
      return container;
    }

    function createRepoAnalysisElement(analysis) {
      const container = document.createElement('div');
      container.className = 'repo-analysis';
      container.textContent = analysis;
      return container;
    }

    function createCodeDisplay(codeLines, dangerousLines) {
      const container = document.createElement('div');
      container.className = 'code-display';

      codeLines.forEach((line, index) => {
        const lineNumber = index + 1;
        const lineElement = document.createElement('div');
        lineElement.className = 'code-line';
        lineElement.textContent = `${lineNumber}: ${line}`;

        const dangerInfo = dangerousLines.find(d => d.line_number == lineNumber);
        if (dangerInfo) {
          lineElement.classList.add('dangerous-line');
        }

        container.appendChild(lineElement);
      });

      return container;
    }

    function createThreatInfo(dangerousLines, category) {
      const container = document.createElement('div');
      container.className = 'threat-info';

      const statusClass = category === 'Безопасный код' ? 'status-safe' :
                        category.includes('Потенциально') ? 'status-warning' : 'status-danger';

      container.innerHTML = `
        <div class="result-header">
          <h3>Результат анализа</h3>
          <span class="result-status ${statusClass}">${category}</span>
        </div>
      `;

      if (dangerousLines && dangerousLines.length > 0) {
        const threatsTitle = document.createElement('h4');
        threatsTitle.textContent = 'Обнаруженные угрозы:';
        container.appendChild(threatsTitle);

        dangerousLines.forEach(threat => {
          const threatElement = document.createElement('div');
          threatElement.className = 'threat-item';
          threatElement.innerHTML = `
            <div class="threat-line">Строка ${threat.line_number}:</div>
            <div class="threat-code">${threat.code}</div>
            <div class="threat-reason">${threat.reason}</div>
          `;
          container.appendChild(threatElement);
        });
      } else {
        const noThreats = document.createElement('div');
        noThreats.textContent = 'Угроз не обнаружено';
        container.appendChild(noThreats);
      }

      return container;
    }

    function analyze(type) {
      const output = type === 'code'
        ? document.getElementById('single-result')
        : document.getElementById('repo-single-result');

      const resultsContainer = type === 'code'
        ? document.getElementById('code-analysis-container')
        : document.getElementById('repo-results-list');

      const repoInfoContainer = document.getElementById('repo-info-container');
      const repoAnalysisContainer = document.getElementById('repo-analysis-container');

      output.innerHTML = '';
      resultsContainer.innerHTML = '';
      repoInfoContainer.innerHTML = '';
      repoAnalysisContainer.innerHTML = '';

      if (type === 'code') {
        const code = document.getElementById('codeInput').value;
        if (!code.trim()) {
          output.innerHTML = '<span style="color: #ff6584;">Пожалуйста, введите код для анализа</span>';
          return;
        }

        output.innerHTML = '<span style="color: #64ffda;">Анализируем код, пожалуйста подождите...</span>';

        const codeLines = code.split('\n');

        fetch('/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ code: code })
        })
        .then(response => response.json())
        .then(data => {
          if (data.error) {
            output.innerHTML = `<span style="color: #ff6584;">Ошибка: ${data.error}</span>`;
          } else {
            output.innerHTML = '';

            const displayLines = data.full_code || codeLines;

            const codeContainer = document.createElement('div');
            codeContainer.className = 'code-container';

            const codeSection = document.createElement('div');
            codeSection.className = 'code-section';
            codeSection.appendChild(createCodeDisplay(displayLines, data.dangerous_lines || []));

            const threatSection = document.createElement('div');
            threatSection.className = 'code-section';
            threatSection.appendChild(createThreatInfo(data.dangerous_lines || [], data.analysis || 'Неизвестно'));

            codeContainer.appendChild(codeSection);
            codeContainer.appendChild(threatSection);
            resultsContainer.appendChild(codeContainer);

            updateChart();
          }
        })
        .catch(error => {
          output.innerHTML = `<span style="color: #ff6584;">Произошла ошибка: ${error.message}</span>`;
        });
      }
      else if (type === 'repo') {
        const githubUrl = document.getElementById('githubUrl').value;
        if (!githubUrl.trim()) {
          output.innerHTML = '<span style="color: #ff6584;">Пожалуйста, введите URL репозитория</span>';
          return;
        }

        output.innerHTML = '<span style="color: #64ffda;">Анализируем репозиторий, пожалуйста подождите...</span>';

        fetch('/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ github_url: githubUrl })
        })
        .then(response => response.json())
        .then(data => {
          if (data.error) {
            output.innerHTML = `<span style="color: #ff6584;">Ошибка: ${data.error}</span>`;
          } else {
            output.innerHTML = `<strong>${data.code_analysis}</strong>`;

            if (data.repo_info) {
              repoInfoContainer.appendChild(createRepoInfoElement(data.repo_info));
            }

            if (data.repo_analysis) {
              repoAnalysisContainer.appendChild(createRepoAnalysisElement(data.repo_analysis));
            }

            if (data.details && data.details.length > 0) {
              data.details.forEach(file => {
                const fileResult = document.createElement('div');
                fileResult.className = 'file-result';

                const statusClass = file.result.includes('Безопасный') ? 'status-safe' :
                                  file.result.includes('Потенциально') ? 'status-warning' : 'status-danger';

                fileResult.innerHTML = `
                  <div class="result-header">
                    <div><strong>Файл:</strong> ${file.file}</div>
                    <span class="result-status ${statusClass}">${file.result}</span>
                  </div>
                `;

                if (file.dangerous_lines && file.dangerous_lines.length > 0) {
                  const codeContainer = document.createElement('div');
                  codeContainer.className = 'code-container';

                  const codeSection = document.createElement('div');
                  codeSection.className = 'code-section';
                  codeSection.appendChild(createCodeDisplay(file.full_code, file.dangerous_lines));

                  const threatSection = document.createElement('div');
                  threatSection.className = 'code-section';
                  threatSection.appendChild(createThreatInfo(file.dangerous_lines, file.result));

                  codeContainer.appendChild(codeSection);
                  codeContainer.appendChild(threatSection);
                  fileResult.appendChild(codeContainer);
                }

                resultsContainer.appendChild(fileResult);
              });
            }

            updateChart();
          }
        })
        .catch(error => {
          output.innerHTML = `<span style="color: #ff6584;">Произошла ошибка: ${error.message}</span>`;
        });
      }
    }

    document.addEventListener('DOMContentLoaded', () => {
      initChart();
      updateChart();
    });