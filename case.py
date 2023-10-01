from pert import PERT
import numpy as np
import matplotlib.pyplot as plt

SHOW_PLOT = False

IMG_PATH = '<PATH>'

AXIS_FONTSIZE = 13.0


COLOR_DETECTION = 'teal'
COLOR_OTHER = 'cadetblue'

_SEED = 42
ROUNDS = 1_000_000


def run():
    tcap = PlotConfig('Threat Capability (TCap)', 30, 55, 90, color=COLOR_OTHER)
    print(tcap)
    plot_histogram([tcap], 'TCap', 'Density', 'uc_tcap')

    if_lef = simulate_if(tcap)
    np_lef = simulate_np(tcap, if_lef)
    simulate_aoo(tcap, np_lef)


def simulate_if(tcap):
    tef = PlotConfig('Threat Event Frequency (TEF)', 40, 220, 300, color=COLOR_OTHER)
    print(tef)
    plot_histogram([tef], 'TEF (p.a.)', 'Density', 'uc_if_tef')

    ips = PlotConfig('RS - Intrusion Protection System (IPS)', 50, 70, 95, 1.0)
    edr = PlotConfig('RS - Endpoint Detection and Response (EDR)', 60, 85, 95, 0.7)
    ua = PlotConfig('RS - User Awareness', 10, 30, 95, 0.99)
    ubl = PlotConfig('RS - URL Block List', 40, 80, 90, 1.0)

    print(ips)
    print(edr)
    print(ua)
    print(ubl)

    plot_histogram([ips, edr, ua, ubl], 'Resistance Strength (RS)', 'Density', 'uc_if_rs')

    attacker_wins = 0
    true_count = 0
    false_count = 0
    for i in range(len(tcap.v)):
        if tcap.v[i] > max([ips.v[i], edr.v[i], ua.v[i], ubl.v[i]]):
            attacker_wins += 1
            if true_count <= 3:
                print('P: ' + get_printable_table_row([tcap.v[i], ips.v[i], edr.v[i], ua.v[i], ubl.v[i], 1]))
                true_count += 1
        else:
            if false_count <= 3:
                print('P: ' + get_printable_table_row([tcap.v[i], ips.v[i], edr.v[i], ua.v[i], ubl.v[i], 0]))
                false_count += 1

    vuln = attacker_wins / ROUNDS
    print(f'\nIF Vulnerability: {round(vuln, 5)}\n')

    lef = PlotConfig('Initial Foothold LEF', vector=tef.v * vuln, color=COLOR_OTHER)
    print(lef)
    plot_histogram([lef], 'LEF (p.a.)', 'Density', 'uc_if_lef')

    return lef


def simulate_np(tcap, tef):
    # Protection
    ld_p = PlotConfig('RS P - Local Discovery: Secure Configuration', 0, 10, 30, 1.0)  # Unprivileged local discovery
    rd_p_ns = PlotConfig('RS P - Remote Discovery: Network Segmentation', 85, 95, 100, 0.55)  # 55% of servers are fully segmented / unprivileged remote discovery

    plot_histogram([ld_p, rd_p_ns], 'Resistance Strength (RS)', 'Density', 'uc_np_discovery_p')

    # Detection
    ld_d = PlotConfig('RS D - Local Discovery: Monitoring', 10, 30, 50, 1.0, color=COLOR_DETECTION)
    rd_d_ns = PlotConfig('RS D - Remote Discovery: Network IPS', 30, 50, 80, 0.55, color=COLOR_DETECTION)  # Network IPS

    plot_histogram([ld_d, rd_d_ns], 'Resistance Strength (RS)', 'Density', 'uc_np_discovery_d')

    # Exploit of Remote Service
    rs_eors_p_fw = PlotConfig('RS P - EoRS: Firewall', 30, 50, 70, 0.7)
    rs_eors_p_sc = PlotConfig('RS P - EoRS: Secure Configuration', 80, 90, 95, 0.8)
    rs_eors_p_sd = PlotConfig('RS P - EoRS: Secure Software Development', 10, 40, 70, 0.8)
    rs_eors_p_vm = PlotConfig('RS P - EoRS: Vulnerability Management', 60, 85, 95, 0.9)
    rs_eors_p_complement_v = np.concatenate([np.array_split(rs_eors_p_sd.v, 2)[0], np.array_split(rs_eors_p_vm.v, 2)[0]])
    np.random.default_rng(seed=get_next_seed()).shuffle(rs_eors_p_complement_v)
    rs_eors_p_complement = PlotConfig('P RS - EoRS: Vulnerability Management\nand Secure Software Development', vector=rs_eors_p_complement_v)

    plot_histogram([rs_eors_p_fw, rs_eors_p_sc, rs_eors_p_complement], 'Resistance Strength (RS)', 'Density', 'uc_np_eors_p')

    rs_eors_d_fw = PlotConfig('RS D - EoRS: Firewall', 10, 40, 60, 0.7, color=COLOR_DETECTION)
    rs_eors_d_mon = PlotConfig('RS D - EoRS: Default Monitoring', 0, 30, 60, 0.95, color=COLOR_DETECTION)

    plot_histogram([rs_eors_d_fw, rs_eors_d_mon], 'Resistance Strength (RS)', 'Density', 'uc_np_eors_d')

    attacker_wins = 0
    true_p_count = 0
    true_d_count = 0
    false_d_count = 0
    false_p_count = 0
    for i in range(len(tcap.v)):
        if tcap.v[i] < max([ld_d.v[i], rd_d_ns.v[i], rs_eors_d_fw.v[i], rs_eors_d_mon.v[i]]):
            # Attack gets detected -> Vuln does not increase
            if false_d_count <= 3:
                print('D: ' + get_printable_table_row([tcap.v[i], ld_d.v[i], rd_d_ns.v[i], rs_eors_d_fw.v[i], rs_eors_d_mon.v[i], 1]))
                false_d_count += 1
            continue
        else:
            if true_d_count <= 3:
                print('D: ' + get_printable_table_row([tcap.v[i], ld_d.v[i], rd_d_ns.v[i], rs_eors_d_fw.v[i], rs_eors_d_mon.v[i], 1]))
                true_d_count += 1

        if tcap.v[i] > max([ld_p.v[i], rd_p_ns.v[i], rs_eors_p_fw.v[i], rs_eors_p_complement.v[i], rs_eors_p_sc.v[i]]):
            attacker_wins += 1
            if true_d_count <= 3:
                print('P: ' + get_printable_table_row([tcap.v[i], ld_p.v[i], rd_p_ns.v[i], rs_eors_p_fw.v[i], rs_eors_p_complement.v[i], rs_eors_p_sc.v[i], 0]))
                true_p_count += 1
        else:
            if false_p_count <= 3:
                print('P: ' + get_printable_table_row([tcap.v[i], ld_p.v[i], rd_p_ns.v[i], rs_eors_p_fw.v[i], rs_eors_p_complement.v[i], rs_eors_p_sc.v[i], 0]))
                false_p_count += 1
            # Attacker is not strong enough and gives up
            continue

    vuln = attacker_wins / ROUNDS
    print(f'\nNP Vulnerability: {round(vuln, 5)}\n')

    lef = PlotConfig('Network Propagation LEF', vector=tef.v * vuln, color=COLOR_OTHER)
    print(lef)
    plot_histogram([lef], 'LEF (p.a.)', 'Density', 'uc_np_lef')

    return lef


def simulate_aoo(tcap, tef):
    dlp_p = PlotConfig('RS P - Data Loss Prevention (DLP)', 10, 40, 80, 1.0)
    dlp_d = PlotConfig('RS D - Data Loss Prevention (DLP)', 10, 40, 80, 1.0, color=COLOR_DETECTION)  # Assuming the exfiltration is detected before the dmg is done

    plot_histogram([dlp_p, dlp_d], 'Resistance Strength (RS)', 'Density', 'uc_aao_dlp')

    attacker_wins = 0
    for i in range(len(tcap.v)):
        if tcap.v[i] < max([dlp_d.v[i]]):
            # Attack gets detected -> Vuln does not increase
            continue

        if tcap.v[i] > max([dlp_p.v[i]]):
            attacker_wins += 1
        else:
            # Attacker is not strong enough and gives up
            continue

    vuln = attacker_wins / ROUNDS
    print(f'\nAoO Vulnerability: {round(vuln, 5)}\n')

    lef = PlotConfig('Action on Objectives LEF', vector=tef.v * vuln, color=COLOR_OTHER)
    print(lef)
    plot_histogram([lef], 'LEF (p.a.)', 'Density', 'uc_aao_lef')

    return lef


def get_next_seed():
    global _SEED
    _SEED += 1
    return _SEED


def get_printable_table_row(values):
    return '&'.join([str(round(x, 1)) for x in values])


def avg(a, decimals=3):
    return round(np.average(a), decimals)


def percentile(a, perc=90, decimals=3):
    return round(np.percentile(a, perc), decimals)


def most_likely(a, b=None):
    histogram = np.histogram(a, bins='auto', density=True)
    argmax = np.argmax(histogram[0])
    bins = histogram[1]
    ml = (bins[argmax] + bins[argmax + 1]) / 2

    if b is None:
        return round(ml, 3)
    else:
        histogram_b = np.histogram(b, bins=bins, density=True)
        argmax_b = np.argmax(histogram_b[0])
        ml_b = (bins[argmax_b] + bins[argmax_b + 1]) / 2
        return ml, ml_b


def plot_histogram(plot_configs, xlabel, ylabel, file_name):
    number_plots = len(plot_configs)
    fig, axs = plt.subplots(number_plots, 1)
    fig.set_figwidth(7)
    fig.set_figheight(number_plots * 3)

    if number_plots == 1:
        axs = [axs]
        fig.set_figheight(6)
        fig.set_figwidth(8)

    common_plot(fig, plot_configs)

    for i in range(number_plots):
        axs[i].set_ylabel(ylabel, fontsize=AXIS_FONTSIZE)
        if i == (number_plots - 1):
            axs[i].set_xlabel(xlabel, fontsize=AXIS_FONTSIZE)

    plt.subplots_adjust(wspace=0.2, hspace=0.9)

    plt.savefig(IMG_PATH + file_name + '.png', bbox_inches='tight', dpi=300)
    if SHOW_PLOT:
        plt.show()


def common_plot(fig, plot_configs):
    ax_plots = zip(fig.axes, plot_configs)
    for ax, pc in ax_plots:
        counts, bins = np.histogram(pc.v, bins='auto', density=True)
        if len(bins) < 100:
            counts, bins = np.histogram(pc.v, bins=100, density=True)
        elif len(bins) > 200:
            counts, bins = np.histogram(pc.v, bins=200, density=True)
        # print(f'Bins: {len(bins)}')
        histtype = 'step'  # step or bar
        ax.hist(bins[:-1], bins, histtype=histtype, weights=counts, color=pc.color)
        if pc.is_derived():
            title = f'{pc.title} \n' \
                    f'10th: {round(pc.ten, 2)}, Avg: {round(pc.avg, 2)}, 90th: {round(pc.ninety, 2)}'
        elif '(TCap)' in pc.title or '(TEF)' in pc.title:
            title = f'{pc.title} \n' \
                    f'Min: {pc.min}, ML: {pc.ml}, Max: {pc.max}\n' \
                    f'10th: {round(pc.ten, 1)}, Avg: {round(pc.avg, 1)}, 90th: {round(pc.ninety, 1)}'
        # elif 'LEF' in pc.title:
        #     title = f'{pc.title} \n' \
        #             f'Min: {pc.min}, ML: {pc.ml}, Max: {pc.max}\n' \
        #             f'10th: {round(pc.ten, 2)}, Avg: {round(pc.avg, 2)}, 90th: {round(pc.ninety, 2)}'
        else:
            title = f'{pc.title} \n' \
                    f'Min: {pc.min}, ML: {pc.ml}, Max: {pc.max}, Coverage: {round(pc.coverage * 100)}%\n' \
                    f'10th: {round(pc.ten, 1)}, Avg: {round(pc.avg, 1)}, 90th: {round(pc.ninety, 1)}'
        ax.set_title(title, fontsize=13.0)
        ax.tick_params(axis='x', labelsize=AXIS_FONTSIZE)
        ax.tick_params(axis='y', labelsize=AXIS_FONTSIZE)
        if not pc.is_derived() and '(TEF)' not in pc.title:
            ax.set_xlim([0, 100])


class PlotConfig:

    def __init__(self, title, pert_min=None, pert_ml=None, pert_max=None, coverage=1.0, vector=None, color=None):
        self.title = title
        self.min = pert_min
        self.ml = pert_ml
        self.max = pert_max
        self.coverage = coverage
        self.color = color
        self.pert = PERT(pert_min, pert_ml, pert_max) if vector is None else None
        self.v = get_rs_vector(self.pert, self.coverage) if vector is None else vector
        self.ten = percentile(self.v, perc=10, decimals=9)
        self.ninety = percentile(self.v, perc=90, decimals=9)
        self.avg = avg(self.v, 9)

    def __str__(self):
        return f'{self.title} 10th: {round(self.ten, 3)}\n' \
               f'{self.title}   ML: {round(most_likely(self.v), 3)}\n' \
               f'{self.title}  AVG: {round(self.avg, 3)}\n' \
               f'{self.title} 90th: {round(self.ninety, 3)}\n'

    def is_derived(self):
        return self.pert is None


def get_rs_vector(pert, control_coverage):
    control_rs_vector = pert.rvs(ROUNDS, random_state=get_next_seed())

    coverage_vector = np.zeros(len(control_rs_vector))
    coverage_vector[:round(control_coverage * len(control_rs_vector))] = 1
    np.random.default_rng(seed=get_next_seed()).shuffle(coverage_vector)

    rs_vector = control_rs_vector * coverage_vector
    return rs_vector


run()
